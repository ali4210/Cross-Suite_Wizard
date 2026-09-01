package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/vault"
)

const (
	Reset       = "\033[0m"
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Magenta     = "\033[35m"
	Cyan        = "\033[36m"
	Bold        = "\033[1m"
	Dim         = "\033[2m"
	BgDark      = "\033[48;5;236m"
	BgHighlight = "\033[48;5;24m"
)

type NotificationItem struct {
	ID        int       `json:"id"`
	SenderIP  string    `json:"sender_ip"`
	SenderTag string    `json:"sender_tag"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	IsRead    bool      `json:"is_read"`
}

func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// RenderEnterpriseHUD draws the telemetry top panel with background VoIP & live notification status
func RenderEnterpriseHUD(targetDisplay, port, user string, targetOS osdetect.TargetOS, isAdmin, isActive bool, activeTunnelsCount int, isVoIPActive bool, voipPeer string) {
	unreadCount, latestMsgFormatted := getFormattedNotificationTelemetry()

	width := 69
	borderTop := "┌" + strings.Repeat("─", width-2) + "┐"
	borderMid := "├" + strings.Repeat("─", width-2) + "┤"
	borderBot := "└" + strings.Repeat("─", width-2) + "┘"

	fmt.Println(Cyan + Bold + borderTop + Reset)

	if isActive && targetDisplay != "" {
		roleTag := "User"
		if isAdmin {
			roleTag = "Admin"
		}
		line1 := fmt.Sprintf(" ACTIVE: %s@%s:%s [%s|%s]", user, targetDisplay, port, targetOS, roleTag)
		fmt.Printf(Cyan+Bold+"│"+Green+Bold+" %-65s "+Cyan+Bold+"│\n"+Reset, truncateRawString(line1, 65))
	} else {
		fmt.Printf(Cyan+Bold+"│"+Yellow+Bold+" %-65s "+Cyan+Bold+"│\n"+Reset, "ACTIVE: None (Select Hub [1] to lock target or unlock Vault)")
	}

	fmt.Println(Cyan + Bold + borderMid + Reset)

	// Status Line 2: VoIP status combined with real-time notifications
	line2Text := ""
	if isVoIPActive {
		line2Text = fmt.Sprintf(Green+Bold+"🎙️ VOIP LIVE: [%s]"+Reset+" | "+Yellow+"MIC: TRANSMITTING"+Reset, truncateRawString(voipPeer, 20))
	} else if unreadCount > 0 && latestMsgFormatted != "" {
		line2Text = fmt.Sprintf(Magenta+Bold+"TUNNELS: %d"+Reset+" | %s", activeTunnelsCount, latestMsgFormatted)
	} else {
		line2Text = fmt.Sprintf(Magenta+Bold+"TUNNELS: %d Active"+Reset+" | "+Dim+"NOTIFS: 0 New"+Reset, activeTunnelsCount)
	}

	fmt.Printf(Cyan+Bold+"│"+Reset+" %s "+Cyan+Bold+"│\n"+Reset, padAnsiLine(line2Text, 65))
	fmt.Println(Cyan + Bold + borderBot + Reset)
}

func getFormattedNotificationTelemetry() (int, string) {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	} else if err != nil {
		home = "."
	}
	notifPath := filepath.Join(home, ".cross-ssh", "notifications.json")
	data, err := os.ReadFile(notifPath)
	if err != nil {
		return 0, ""
	}

	lines := strings.Split(string(data), "\n")
	count := 0
	formattedMsg := ""

	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var item NotificationItem
		if err := json.Unmarshal([]byte(l), &item); err == nil && !item.IsRead {
			count++
			senderTag := vault.ResolveAliasForIP(item.SenderIP)
			if senderTag == "" {
				senderTag = item.SenderIP
			}

			// Format by notification type with color tags
			switch item.Type {
			case "VOICE_MEMO":
				formattedMsg = fmt.Sprintf(Yellow+Bold+"🎙️ [VOICE MEMO from %s]:"+Reset+Cyan+" %s"+Reset, senderTag, truncateRawString(item.Message, 28))
			case "CALL":
				formattedMsg = fmt.Sprintf(Green+Bold+"📞 [INCOMING CALL from %s]"+Reset, senderTag)
			case "MSG":
				formattedMsg = fmt.Sprintf(Magenta+Bold+"💬 [MSG from %s]:"+Reset+" %s", senderTag, truncateRawString(item.Message, 28))
			default:
				formattedMsg = fmt.Sprintf(Yellow+Bold+"🔔 [%s from %s]:"+Reset+" %s", item.Type, senderTag, truncateRawString(item.Message, 28))
			}
		}
	}
	return count, formattedMsg
}

func truncateRawString(str string, maxLen int) string {
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}

func padAnsiLine(rendered string, targetVisibleLen int) string {
	// Strip ANSI to calculate actual terminal display length
	visibleLen := len(stripAnsi(rendered))
	if visibleLen < targetVisibleLen {
		return rendered + strings.Repeat(" ", targetVisibleLen-visibleLen)
	}
	return rendered
}

func stripAnsi(str string) string {
	var sb strings.Builder
	inEscape := false
	for i := 0; i < len(str); i++ {
		if str[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if str[i] == 'm' {
				inEscape = false
			}
			continue
		}
		sb.WriteByte(str[i])
	}
	return sb.String()
}