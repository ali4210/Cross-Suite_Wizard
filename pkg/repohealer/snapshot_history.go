package repohealer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SnapshotHistoryEntry is one row of Option 9's unified "change history": every option that
// snapshots something before modifying the target appends one of these, in addition to (never
// instead of) that option's own existing audit record and the underlying snapshot itself. It is
// deliberately a superset view over the pre-existing per-feature audit files (Deb822, APT-list,
// generic APT repair, custom-repo injection), not a replacement for them.
type SnapshotHistoryEntry struct {
	Timestamp      time.Time `json:"timestamp"`
	Target         string    `json:"target,omitempty"`
	Option         string    `json:"option"`
	Action         string    `json:"action"`
	SnapshotID     string    `json:"snapshot_id,omitempty"`
	SnapshotPath   string    `json:"snapshot_path,omitempty"`
	FilesTouched   []string  `json:"files_touched,omitempty"`
	PackageManager string    `json:"package_manager,omitempty"`
	PackageList    string    `json:"package_list,omitempty"`
	Result         string    `json:"result"`
}

const (
	snapshotHistoryPathEnv     = "CROSS_SUITE_SNAPSHOT_HISTORY_PATH"
	defaultSnapshotHistoryPath = "/var/log/cross-suite/snapshot-history.jsonl"

	// SnapshotHistoryResultApplied etc. are the Result values Option 9's history view expects;
	// any gated flow recording a history entry should use one of these rather than inventing
	// its own ad hoc string, so the history view's grouping/coloring stays meaningful.
	SnapshotHistoryResultApplied          = "applied"
	SnapshotHistoryResultFailed           = "failed"
	SnapshotHistoryResultRolledBack       = "rolled_back"
	SnapshotHistoryResultBlocked          = "blocked"
	SnapshotHistoryResultDeclined         = "declined"
	SnapshotHistoryResultManualCheckpoint = "manual_checkpoint"
	SnapshotHistoryResultRestored         = "restored"
)

// SnapshotHistoryPath returns the local (controller-side) path the unified change-history
// ledger is appended to, mirroring the CROSS_SUITE_*_AUDIT_PATH env-override convention every
// other audit log in this package already uses.
func SnapshotHistoryPath() string {
	if path := strings.TrimSpace(os.Getenv(snapshotHistoryPathEnv)); path != "" {
		return path
	}
	return defaultSnapshotHistoryPath
}

// AppendSnapshotHistoryEntry appends one JSON-Lines record to the history ledger.
func AppendSnapshotHistoryEntry(path string, entry SnapshotHistoryEntry) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("snapshot history path is empty")
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create snapshot history directory %q: %w", parent, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open snapshot history file %q: %w", path, err)
	}
	defer file.Close()

	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode snapshot history entry: %w", err)
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("append snapshot history entry to %q: %w", path, err)
	}

	return nil
}

// ListSnapshotHistory reads every entry from the ledger, newest first. A malformed line is
// skipped rather than failing the whole read, since the ledger is append-only operational data,
// not a transactional log — one bad line must not hide every other entry.
func ListSnapshotHistory(path string) ([]SnapshotHistoryEntry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("snapshot history path is empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read snapshot history file %q: %w", path, err)
	}

	var entries []SnapshotHistoryEntry
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry SnapshotHistoryEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// ListSnapshotHistoryForTarget filters ListSnapshotHistory's result to entries recorded against
// the given target identity (e.g. client.RemoteAddr().String()), so an operator managing
// multiple hosts from the same controller never sees another host's history mixed in. An empty
// target matches every entry (useful for a "show everything" view).
func ListSnapshotHistoryForTarget(path, target string) ([]SnapshotHistoryEntry, error) {
	entries, err := ListSnapshotHistory(path)
	if err != nil {
		return nil, err
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return entries, nil
	}

	var filtered []SnapshotHistoryEntry
	for _, entry := range entries {
		if entry.Target == target {
			filtered = append(filtered, entry)
		}
	}
	return filtered, nil
}

// DiffPackageLists renders a simple, line-based added/removed diff between two captured
// package-list snapshots (the raw text CapturePackageList* functions return). It is
// intentionally not a semantic version-aware diff — just enough to show an operator what
// changed between two checkpoints, which lines were added, and which were removed.
func DiffPackageLists(before, after string) string {
	beforeLines := nonEmptyLineSet(before)
	afterLines := nonEmptyLineSet(after)

	var added, removed []string
	for line := range afterLines {
		if !beforeLines[line] {
			added = append(added, line)
		}
	}
	for line := range beforeLines {
		if !afterLines[line] {
			removed = append(removed, line)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	if len(added) == 0 && len(removed) == 0 {
		return "No package list differences."
	}

	var builder strings.Builder
	for _, line := range added {
		builder.WriteString("+ " + line + "\n")
	}
	for _, line := range removed {
		builder.WriteString("- " + line + "\n")
	}
	return strings.TrimRight(builder.String(), "\n")
}

func nonEmptyLineSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	return set
}

// CapturePackageListScript returns the read-only shell command that captures the installed
// (and, where the manager distinguishes it, explicitly/manually installed) package list for
// the given manager. Every one of these is read-only: it never installs, removes, or modifies
// anything. Returns ("", false) for a manager with no supported capture (e.g. emerge, which
// stays diagnose-only in this tool; Homebrew, which captures its package list as a full
// Brewfile via CreateHomebrewSnapshot instead of this text form).
func CapturePackageListScript(manager PackageManager) (string, bool) {
	switch manager {
	case ManagerAPT:
		return `set +e
echo '--- dpkg --get-selections ---'
dpkg --get-selections 2>/dev/null
echo '--- apt-mark showmanual ---'
apt-mark showmanual 2>/dev/null
`, true
	case ManagerDNF, ManagerYUM:
		return `set +e
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort
`, true
	case ManagerZypper:
		return `set +e
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort
`, true
	case ManagerPacman:
		return `set +e
pacman -Qe 2>/dev/null
`, true
	case ManagerAPK:
		return `set +e
apk info -v 2>/dev/null | sort
`, true
	case ManagerXBPS:
		return `set +e
xbps-query -l 2>/dev/null | sort
`, true
	default:
		return "", false
	}
}

// CapturePackageList runs CapturePackageListScript's read-only command over the given
// Executor's non-privileged Run channel (every one of these commands works for a normal user
// on every supported manager) and returns its trimmed output. It returns ("", false) for an
// unsupported manager without running anything.
func CapturePackageList(exec Executor, manager PackageManager) (string, bool) {
	script, ok := CapturePackageListScript(manager)
	if !ok {
		return "", false
	}

	out, err := exec.Run(script)
	if err != nil {
		return strings.TrimSpace(out), true
	}
	return strings.TrimSpace(out), true
}

// SnapshotRetentionCount returns the configured number of checkpoints to keep (Option 9's
// "Delete old checkpoints"), defaulting to 20, overridable via CROSS_SUITE_SNAPSHOT_RETENTION.
// A non-positive or unparsable override falls back to the default rather than disabling
// retention entirely — "keep nothing" is never a safe default for a rollback mechanism.
func SnapshotRetentionCount() int {
	const defaultRetention = 20

	raw := strings.TrimSpace(os.Getenv("CROSS_SUITE_SNAPSHOT_RETENTION"))
	if raw == "" {
		return defaultRetention
	}

	count, err := strconv.Atoi(raw)
	if err != nil || count <= 0 {
		return defaultRetention
	}
	return count
}

// SnapshotIDsToPrune decides which snapshot IDs "Delete old checkpoints" should remove, given
// every known snapshot ID newest-first and the configured retention count. It never prunes
// below one remaining snapshot, even if retention is configured to 0 or 1 is somehow passed in,
// so a pending change always has something to roll back to.
func SnapshotIDsToPrune(idsNewestFirst []string, retain int) []string {
	if retain < 1 {
		retain = 1
	}
	if len(idsNewestFirst) <= retain {
		return nil
	}
	return append([]string(nil), idsNewestFirst[retain:]...)
}
