package transfer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/term"
)

const (
	Reset        = "\033[0m"
	Red          = "\033[31m"
	Green        = "\033[32m"
	Yellow       = "\033[33m"
	Blue         = "\033[34m"
	Magenta      = "\033[35m"
	Cyan         = "\033[36m"
	Bold         = "\033[1m"
	BgBlue       = "\033[44m"
	White        = "\033[37m"
	ItemsPerPage = 12
)

type FileItem struct {
	Name  string
	IsDir bool
	Path  string
	Size  int64
}

func ResetTerminal() {
	_ = exec.Command("stty", "sane").Run()
}

func EnterAlternateScreen() {
	fmt.Print("\033[?1049h\033[H")
}

func ExitAlternateScreen() {
	fmt.Print("\033[?1049l")
	ResetTerminal()
}

func ReadRealtimeInput(prompt string) string {
	fmt.Print(Bold + prompt + Reset)

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, oldState)
	}

	var input []rune
	buf := make([]byte, 1)

	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}

		b := buf[0]

		if b == '\r' || b == '\n' {
			fmt.Print("\r\n")
			break
		}

		if b == 8 || b == 127 {
			if len(input) > 0 {
				input = input[:len(input)-1]
				fmt.Print("\b \b")
			}
			continue
		}

		if b == 27 {
			continue
		}

		if b < 32 {
			continue
		}

		r := rune(b)
		input = append(input, r)
		fmt.Print(string(r))
	}

	return strings.TrimSpace(string(input))
}

func ReadCleanInput(reader *bufio.Reader, prompt string) string {
	return ReadRealtimeInput(prompt)
}

func sanitizeDisplayPath(p string) string {
	clean := filepath.ToSlash(p)
	if strings.HasPrefix(clean, "/") && len(clean) > 3 && clean[2] == ':' {
		return clean[1:]
	}
	return clean
}

func padCell(text string, width int) string {
	if len(text) > width {
		return text[:width]
	}
	return text + strings.Repeat(" ", width-len(text))
}

func splitWrap(text string, maxLen int) []string {
	if len(text) == 0 {
		return []string{""}
	}
	var lines []string
	for len(text) > maxLen {
		lines = append(lines, text[:maxLen])
		text = text[maxLen:]
	}
	if len(text) > 0 {
		lines = append(lines, text)
	}
	return lines
}

func maxLen(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func formatSize(size int64, isDir bool) string {
	if isDir {
		return "DIR / FOLDER"
	}
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024.0)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024.0*1024.0))
	}
	return fmt.Sprintf("%.2f GB", float64(size)/(1024.0*1024.0*1024.0))
}

// ====================================================================
//  GOLD-STANDARD BOX-DRAWING BROWSER TABLE RENDERER
// ====================================================================
// Helper to measure terminal display width accurately for ASCII & Unicode
func runeWidth(r rune) int {
	// Standard emoji and wide Asian characters occupy 2 visual columns
	if r >= 0x1F300 && r <= 0x1FAFF {
		return 2
	}
	if r >= 0x2600 && r <= 0x27BF {
		return 2
	}
	return 1
}

func visualWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func padCellVisual(text string, targetWidth int) string {
	curWidth := visualWidth(text)
	if curWidth > targetWidth {
		// Truncate runes until it fits
		runes := []rune(text)
		for len(runes) > 0 && visualWidth(string(runes)) > targetWidth {
			runes = runes[:len(runes)-1]
		}
		text = string(runes)
		curWidth = visualWidth(text)
	}
	return text + strings.Repeat(" ", targetWidth-curWidth)
}

func splitWrapVisual(text string, maxLen int) []string {
	if len(text) == 0 {
		return []string{""}
	}
	var lines []string
	runes := []rune(text)
	for len(runes) > maxLen {
		lines = append(lines, string(runes[:maxLen]))
		runes = runes[maxLen:]
	}
	if len(runes) > 0 {
		lines = append(lines, string(runes))
	}
	return lines
}

func renderGoldStandardBrowserTable(title, location string, items []FileItem, selectedIdx, viewStart, viewEnd, totalItems int) {
	// 1. Clear screen & position cursor at top-left explicitly
	fmt.Print("\033[H\033[2J")

	const (
		wNo   = 4
		wType = 14
		wName = 40
		wSize = 14
		wStat = 12
	)

	fmt.Printf("%s%s====================================================================================================%s\r\n", Cyan, Bold, Reset)
	fmt.Printf("%s%s=== %s ===%s\r\n", Cyan, Bold, title, Reset)
	fmt.Printf("%s%s====================================================================================================%s\r\n", Cyan, Bold, Reset)
	fmt.Printf("=> Location: %s%s%s\r\n", Yellow+Bold, location, Reset)
	fmt.Printf("%sControls: [↑/↓ Keys] Navigate | [ENTER] Open / Select | [S] Select Folder | [0/Q] Exit%s\r\n", Yellow, Reset)
	fmt.Print("\r\n")

	topBorder := fmt.Sprintf("┌─%s─┬─%s─┬─%s─┬─%s─┬─%s─┐",
		strings.Repeat("─", wNo),
		strings.Repeat("─", wType),
		strings.Repeat("─", wName),
		strings.Repeat("─", wSize),
		strings.Repeat("─", wStat),
	)

	midBorder := fmt.Sprintf("├─%s─┼─%s─┼─%s─┼─%s─┼─%s─┤",
		strings.Repeat("─", wNo),
		strings.Repeat("─", wType),
		strings.Repeat("─", wName),
		strings.Repeat("─", wSize),
		strings.Repeat("─", wStat),
	)

	botBorder := fmt.Sprintf("└─%s─┴─%s─┴─%s─┴─%s─┴─%s─┘",
		strings.Repeat("─", wNo),
		strings.Repeat("─", wType),
		strings.Repeat("─", wName),
		strings.Repeat("─", wSize),
		strings.Repeat("─", wStat),
	)

	fmt.Printf("%s%s%s\r\n", Cyan, topBorder, Reset)
	fmt.Printf(Cyan+"│ %s │ %s │ %s │ %s │ %s │\r\n"+Reset,
		Bold+padCellVisual("NO", wNo)+Reset+Cyan,
		Bold+padCellVisual("ENTRY TYPE", wType)+Reset+Cyan,
		Bold+padCellVisual("ITEM NAME / FILENAME", wName)+Reset+Cyan,
		Bold+padCellVisual("SIZE / PAYLOAD", wSize)+Reset+Cyan,
		Bold+padCellVisual("STATUS", wStat)+Reset+Cyan,
	)
	fmt.Printf("%s%s%s\r\n", Cyan, midBorder, Reset)

	if len(items) == 0 {
		emptyMsg := "Directory is empty."
		fmt.Printf("│ %s │\r\n", Yellow+padCellVisual(emptyMsg, wNo+wType+wName+wSize+wStat+12)+Reset)
		fmt.Printf("%s%s%s\r\n", Cyan, botBorder, Reset)
		return
	}

	for i := viewStart; i < viewEnd && i < len(items); i++ {
		item := items[i]
		isSel := (i == selectedIdx)

		noStr := fmt.Sprintf("%d", i+1)
		typeStr := "📄 File"
		statStr := "[READY]"
		if item.IsDir {
			typeStr = "📁 Directory"
			statStr = "[FOLDER]"
		}

		sizeStr := formatSize(item.Size, item.IsDir)
		nameLines := splitWrapVisual(item.Name, wName)

		for r, nLine := range nameLines {
			cNo := ""
			cType := ""
			cSize := ""
			cStat := ""

			if r == 0 {
				cNo = noStr
				cType = typeStr
				cSize = sizeStr
				cStat = statStr
			}

			if isSel {
				fmt.Printf("│ %s │ %s │ %s │ %s │ %s │\r\n",
					BgBlue+White+Bold+padCellVisual(cNo, wNo)+Reset,
					BgBlue+Yellow+Bold+padCellVisual(cType, wType)+Reset,
					BgBlue+White+Bold+padCellVisual(nLine, wName)+Reset,
					BgBlue+Magenta+Bold+padCellVisual(cSize, wSize)+Reset,
					BgBlue+Green+Bold+padCellVisual(cStat, wStat)+Reset,
				)
			} else {
				var nameColor string
				if item.IsDir {
					nameColor = Cyan + Bold
				} else {
					nameColor = White
				}

				fmt.Printf("│ %s │ %s │ %s │ %s │ %s │\r\n",
					White+padCellVisual(cNo, wNo)+Reset,
					Yellow+padCellVisual(cType, wType)+Reset,
					nameColor+padCellVisual(nLine, wName)+Reset,
					Magenta+padCellVisual(cSize, wSize)+Reset,
					Green+padCellVisual(cStat, wStat)+Reset,
				)
			}
		}
	}

	fmt.Printf("%s%s%s\r\n", Cyan, botBorder, Reset)
	fmt.Printf(Cyan+"Showing entries [%d-%d] of %d total items in directory\r\n"+Reset, viewStart+1, viewEnd, totalItems)
}
// ====================================================================
//  INTERACTIVE LOCAL ARROW-KEY BROWSER
// ====================================================================

func BrowseLocalArrowKeys(reader *bufio.Reader, initialDir string) (string, error) {
	currentDir := initialDir
	selectedIndex := 0

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, oldState)
	}

	for {
		entries, err := os.ReadDir(currentDir)
		if err != nil {
			return "", err
		}

		var items []FileItem
		if currentDir != "/" {
			items = append(items, FileItem{Name: ".. (Parent Directory)", IsDir: true, Path: filepath.Dir(currentDir)})
		}

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			items = append(items, FileItem{
				Name:  entry.Name(),
				IsDir: entry.IsDir(),
				Path:  filepath.Join(currentDir, entry.Name()),
				Size:  info.Size(),
			})
		}

		sort.Slice(items, func(i, j int) bool {
			if items[i].IsDir != items[j].IsDir {
				return items[i].IsDir
			}
			return items[i].Name < items[j].Name
		})

		if selectedIndex >= len(items) {
			selectedIndex = 0
		}

		viewStart := selectedIndex - (ItemsPerPage / 2)
		if viewStart < 0 {
			viewStart = 0
		}
		viewEnd := viewStart + ItemsPerPage
		if viewEnd > len(items) {
			viewEnd = len(items)
			viewStart = viewEnd - ItemsPerPage
			if viewStart < 0 {
				viewStart = 0
			}
		}

		displayDir := sanitizeDisplayPath(currentDir)
		renderGoldStandardBrowserTable("INTERACTIVE ARROW-KEY LOCAL BROWSER", displayDir, items, selectedIndex, viewStart, viewEnd, len(items))

		b := make([]byte, 3)
		os.Stdin.Read(b)

		if b[0] == 'q' || b[0] == 'Q' || b[0] == '0' {
			return "", fmt.Errorf("canceled")
		}
		if b[0] == 's' || b[0] == 'S' || b[0] == 19 {
			return currentDir, nil
		}

		if b[0] == 27 && b[1] == 91 {
			switch b[2] {
			case 65: // Up
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 66: // Down
				if selectedIndex < len(items)-1 {
					selectedIndex++
				}
			case 68: // Left
				if currentDir != "/" {
					currentDir = filepath.Dir(currentDir)
					selectedIndex = 0
				}
			}
			continue
		}

		if b[0] == 10 || b[0] == 13 {
			selected := items[selectedIndex]
			if selected.IsDir {
				currentDir = selected.Path
				selectedIndex = 0
			} else {
				return selected.Path, nil
			}
		}
	}
}

// ====================================================================
//  INTERACTIVE REMOTE ARROW-KEY BROWSER (SFTP)
// ====================================================================

func BrowseRemoteArrowKeys(reader *bufio.Reader, sftpClient *sftp.Client, initialDir string) (string, error) {
	currentDir := initialDir
	selectedIndex := 0

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, oldState)
	}

	for {
		cleanPath := filepath.ToSlash(currentDir)
		entries, err := sftpClient.ReadDir(cleanPath)
		if err != nil {
			return "", err
		}

		var items []FileItem
		if cleanPath != "/" {
			parent := filepath.ToSlash(filepath.Dir(cleanPath))
			if parent == "" {
				parent = "/"
			}
			items = append(items, FileItem{Name: ".. (Parent Directory)", IsDir: true, Path: parent})
		}

		for _, entry := range entries {
			items = append(items, FileItem{
				Name:  entry.Name(),
				IsDir: entry.IsDir(),
				Path:  filepath.ToSlash(filepath.Join(cleanPath, entry.Name())),
				Size:  entry.Size(),
			})
		}

		sort.Slice(items, func(i, j int) bool {
			if items[i].IsDir != items[j].IsDir {
				return items[i].IsDir
			}
			return items[i].Name < items[j].Name
		})

		if selectedIndex >= len(items) {
			selectedIndex = 0
		}

		viewStart := selectedIndex - (ItemsPerPage / 2)
		if viewStart < 0 {
			viewStart = 0
		}
		viewEnd := viewStart + ItemsPerPage
		if viewEnd > len(items) {
			viewEnd = len(items)
			viewStart = viewEnd - ItemsPerPage
			if viewStart < 0 {
				viewStart = 0
			}
		}

		displayDir := sanitizeDisplayPath(cleanPath)
		renderGoldStandardBrowserTable("INTERACTIVE ARROW-KEY REMOTE BROWSER (SFTP)", displayDir, items, selectedIndex, viewStart, viewEnd, len(items))

		b := make([]byte, 3)
		os.Stdin.Read(b)

		if b[0] == 'q' || b[0] == 'Q' || b[0] == '0' {
			return "", fmt.Errorf("canceled")
		}
		if b[0] == 's' || b[0] == 'S' || b[0] == 19 {
			return cleanPath, nil
		}

		if b[0] == 27 && b[1] == 91 {
			switch b[2] {
			case 65: // Up
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 66: // Down
				if selectedIndex < len(items)-1 {
					selectedIndex++
				}
			case 68: // Left
				if cleanPath != "/" {
					currentDir = filepath.ToSlash(filepath.Dir(cleanPath))
					selectedIndex = 0
				}
			}
			continue
		}

		if b[0] == 10 || b[0] == 13 {
			selected := items[selectedIndex]
			if selected.IsDir {
				currentDir = selected.Path
				selectedIndex = 0
			} else {
				return selected.Path, nil
			}
		}
	}
}

// ====================================================================
//  PAGINATED NUMBERED LOCAL & REMOTE BROWSERS
// ====================================================================

func BrowseLocalNumbered(reader *bufio.Reader, initialDir string) (string, error) {
	currentDir := initialDir
	currentPage := 0

	for {
		entries, err := os.ReadDir(currentDir)
		if err != nil {
			fmt.Printf(Red+"[!] Cannot read local directory: %v\n"+Reset, err)
			return "", err
		}

		var items []FileItem
		if currentDir != "/" {
			items = append(items, FileItem{Name: ".. (Parent Directory)", IsDir: true, Path: filepath.Dir(currentDir)})
		}

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			items = append(items, FileItem{
				Name:  entry.Name(),
				IsDir: entry.IsDir(),
				Path:  filepath.Join(currentDir, entry.Name()),
				Size:  info.Size(),
			})
		}

		sort.Slice(items, func(i, j int) bool {
			if items[i].IsDir != items[j].IsDir {
				return items[i].IsDir
			}
			return items[i].Name < items[j].Name
		})

		totalPages := (len(items) + ItemsPerPage - 1) / ItemsPerPage
		if totalPages == 0 {
			totalPages = 1
		}
		if currentPage >= totalPages {
			currentPage = totalPages - 1
		}

		startIdx := currentPage * ItemsPerPage
		endIdx := startIdx + ItemsPerPage
		if endIdx > len(items) {
			endIdx = len(items)
		}

		displayDir := sanitizeDisplayPath(currentDir)
		renderGoldStandardBrowserTable("PAGINATED NUMBERED LOCAL BROWSER", displayDir, items, -1, startIdx, endIdx, len(items))

		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [S] Transfer Entire Directory  |  [N] Next Page  |  [P] Previous Page  |  [0/Q] Exit")
		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------" + Reset)
		input := ReadRealtimeInput("Enter item number to open/select: ")
		upper := strings.ToUpper(input)

		switch upper {
		case "S":
			return currentDir, nil
		case "N":
			if currentPage < totalPages-1 {
				currentPage++
			}
			continue
		case "P":
			if currentPage > 0 {
				currentPage--
			}
			continue
		case "0", "Q", "":
			return "", fmt.Errorf("selection canceled")
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(items) {
			continue
		}

		selected := items[idx-1]
		if selected.IsDir {
			currentDir = selected.Path
			currentPage = 0
		} else {
			return selected.Path, nil
		}
	}
}

func BrowseRemoteNumbered(reader *bufio.Reader, sftpClient *sftp.Client, initialDir string) (string, error) {
	currentDir := initialDir
	currentPage := 0

	for {
		cleanPath := filepath.ToSlash(currentDir)
		entries, err := sftpClient.ReadDir(cleanPath)
		if err != nil {
			fmt.Printf(Red+"[!] Cannot read remote directory: %v\n"+Reset, err)
			return "", err
		}

		var items []FileItem
		if cleanPath != "/" {
			parent := filepath.ToSlash(filepath.Dir(cleanPath))
			if parent == "" {
				parent = "/"
			}
			items = append(items, FileItem{Name: ".. (Parent Directory)", IsDir: true, Path: parent})
		}

		for _, entry := range entries {
			items = append(items, FileItem{
				Name:  entry.Name(),
				IsDir: entry.IsDir(),
				Path:  filepath.ToSlash(filepath.Join(cleanPath, entry.Name())),
				Size:  entry.Size(),
			})
		}

		sort.Slice(items, func(i, j int) bool {
			if items[i].IsDir != items[j].IsDir {
				return items[i].IsDir
			}
			return items[i].Name < items[j].Name
		})

		totalPages := (len(items) + ItemsPerPage - 1) / ItemsPerPage
		if totalPages == 0 {
			totalPages = 1
		}
		if currentPage >= totalPages {
			currentPage = totalPages - 1
		}

		startIdx := currentPage * ItemsPerPage
		endIdx := startIdx + ItemsPerPage
		if endIdx > len(items) {
			endIdx = len(items)
		}

		displayDir := sanitizeDisplayPath(cleanPath)
		renderGoldStandardBrowserTable("PAGINATED NUMBERED REMOTE BROWSER (SFTP)", displayDir, items, -1, startIdx, endIdx, len(items))

		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [S] Transfer Entire Directory  |  [N] Next Page  |  [P] Previous Page  |  [0/Q] Exit")
		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------" + Reset)
		input := ReadRealtimeInput("Enter item number to open/select: ")
		upper := strings.ToUpper(input)

		switch upper {
		case "S":
			return cleanPath, nil
		case "N":
			if currentPage < totalPages-1 {
				currentPage++
			}
			continue
		case "P":
			if currentPage > 0 {
				currentPage--
			}
			continue
		case "0", "Q", "":
			return "", fmt.Errorf("selection canceled")
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(items) {
			continue
		}

		selected := items[idx-1]
		if selected.IsDir {
			currentDir = selected.Path
			currentPage = 0
		} else {
			return selected.Path, nil
		}
	}
}

// ====================================================================
//  PATH SELECTOR ENTRYPOINTS
// ====================================================================

func SelectLocalPath(reader *bufio.Reader, isP2POptional ...bool) (string, error) {
	isP2P := len(isP2POptional) > 0 && isP2POptional[0]

	fmt.Println(Cyan + Bold + "\n==================================================================" + Reset)
	fmt.Println(Cyan + Bold + "               LOCAL FILE & DIRECTORY SELECTOR                    " + Reset)
	fmt.Println(Cyan + Bold + "==================================================================" + Reset)
	fmt.Println("  [1] Direct Path Entry (Type exact path, e.g. /home/kali/MyFolder)")
	fmt.Println("  [2] Paginated Local Directory Browser (Type numbers to enter/select)")

	if isP2P {
		fmt.Println(Green + Bold + "  [3] Interactive Arrow-Key Browser ⭐ [RECOMMENDED FOR LOCAL SELECTION]" + Reset)
	} else {
		fmt.Println("  [3] Interactive Arrow-Key Browser (Use ↑/↓/Enter/← keys)")
	}

	fmt.Println(Red + "  [0] Back / Cancel" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	promptMsg := "Select mode [0-3]: "
	if isP2P {
		promptMsg = "Select mode [0-3, default: 3]: "
	}

	method := ReadRealtimeInput(promptMsg)
	homeDir, _ := os.UserHomeDir()

	if isP2P && method == "" {
		method = "3"
	}

	switch method {
	case "0", "B", "b", "Q", "q":
		return "", fmt.Errorf("canceled by user")
	case "1":
		path := ReadRealtimeInput("Enter exact Local File or Directory Path (0 to cancel): ")
		if path == "0" || path == "" {
			return "", fmt.Errorf("canceled by user")
		}
		return path, nil
	case "2":
		return BrowseLocalNumbered(reader, homeDir)
	case "3":
		return BrowseLocalArrowKeys(reader, homeDir)
	default:
		return BrowseLocalArrowKeys(reader, homeDir)
	}
}

func SelectRemotePath(reader *bufio.Reader, sftpClient *sftp.Client, defaultUser string, isP2POptional ...bool) (string, error) {
	isP2P := len(isP2POptional) > 0 && isP2POptional[0]

	fmt.Println(Cyan + Bold + "\n==================================================================" + Reset)
	fmt.Println(Cyan + Bold + "               REMOTE FILE & DIRECTORY SELECTOR                   " + Reset)
	fmt.Println(Cyan + Bold + "==================================================================" + Reset)
	fmt.Println("  [1] Direct Path Entry (Type exact path, e.g. /home/saleem/Desktop)")

	if isP2P {
		fmt.Println(Green + Bold + "  [2] Paginated Remote Directory Browser ⭐ [RECOMMENDED FOR P2P & HIGH-LATENCY RELAYS]" + Reset)
		fmt.Println("  [3] Interactive Arrow-Key Remote Browser (Use ↑/↓/Enter/← keys)")
	} else {
		fmt.Println("  [2] Paginated Remote Directory Browser (Type numbers to enter/select)")
		fmt.Println("  [3] Interactive Arrow-Key Remote Browser (Use ↑/↓/Enter/← keys)")
	}

	fmt.Println(Red + "  [0] Back / Cancel" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	promptMsg := "Select mode [0-3]: "
	if isP2P {
		promptMsg = "Select mode [0-3, default: 2]: "
	}

	method := ReadRealtimeInput(promptMsg)

	initialRemote := "/home/" + defaultUser
	pwd, err := sftpClient.Getwd()
	if err == nil && pwd != "" {
		initialRemote = pwd
	}

	if isP2P && method == "" {
		method = "2"
	}

	switch method {
	case "0", "B", "b", "Q", "q":
		return "", fmt.Errorf("canceled by user")
	case "1":
		path := ReadRealtimeInput("Enter exact Remote File or Directory Path (0 to cancel): ")
		if path == "0" || path == "" {
			return "", fmt.Errorf("canceled by user")
		}
		return path, nil
	case "2":
		return BrowseRemoteNumbered(reader, sftpClient, initialRemote)
	case "3":
		return BrowseRemoteArrowKeys(reader, sftpClient, initialRemote)
	default:
		return BrowseRemoteNumbered(reader, sftpClient, initialRemote)
	}
}