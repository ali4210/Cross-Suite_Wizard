package playbook

import (
	"fmt"
	"os"
	"time"

	"cross-ssh/pkg/repohealer"

	"golang.org/x/crypto/ssh"
)

// targetIdentity returns a stable-enough identifier for the connected host so Option 9's
// change history can be filtered to the currently connected target instead of mixing in every
// other host this controller has ever managed. It is best-effort: an SSH client always has a
// remote address, but a nil client (never expected in practice) falls back to "unknown" rather
// than panicking.
func targetIdentity(client *ssh.Client) string {
	if client == nil {
		return "unknown"
	}
	return client.RemoteAddr().String()
}

// recordSnapshotHistory appends one entry to Option 9's unified change-history ledger. This is
// always in addition to, never instead of, whatever feature-specific audit record the caller
// already writes (Deb822RepairAuditEvent, RepairAuditEvent, etc.) — the ledger is a superset
// index for the "Show change history" / "Restore a chosen checkpoint" UI, not a replacement for
// those existing, already-tested audit trails.
func recordSnapshotHistory(
	client *ssh.Client,
	option string,
	action string,
	snapshotID string,
	snapshotPath string,
	filesTouched []string,
	packageManager repohealer.PackageManager,
	packageList string,
	result string,
) {
	entry := repohealer.SnapshotHistoryEntry{
		Timestamp:      time.Now().UTC(),
		Target:         targetIdentity(client),
		Option:         option,
		Action:         action,
		SnapshotID:     snapshotID,
		SnapshotPath:   snapshotPath,
		FilesTouched:   filesTouched,
		PackageManager: string(packageManager),
		PackageList:    packageList,
		Result:         result,
	}

	path := repohealer.SnapshotHistoryPath()
	if err := repohealer.AppendSnapshotHistoryEntry(path, entry); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+"WARNING: change-history entry could not be persisted to %q: %v\n"+Reset,
			path,
			err,
		)
	}
}
