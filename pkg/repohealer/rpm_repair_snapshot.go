package repohealer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateRPMFileSnapshot and RestoreRPMFileSnapshot reuse the exact same targeted
// file-snapshot engine CreateAPTFileSnapshot/RestoreAPTFileSnapshot use (snapshot.go) —
// it has nothing APT-specific in it beyond the "apt-"/"rpm-" ID prefix convention
// validateAPTFileSnapshotID checks. Only the GPG key side of an RPM repair needs its
// own, different rollback mechanism (see trackImportedRPMGPGKeys / pruneImportedRPMGPGKeys
// in rpm_repair.go): unlike APT's keyring file, `rpm --import` has no simple file to
// snapshot and restore — it mutates the RPM database directly.
func CreateRPMFileSnapshot(exec Executor, files []string) (Snapshot, error) {
	now := time.Now().UTC()

	snapshotID, err := newRPMFileSnapshotID(now)
	if err != nil {
		return Snapshot{
			CreatedAt: now,
			Created:   false,
		}, fmt.Errorf("create RPM snapshot ID: %w", err)
	}

	return createAPTFileSnapshotAtRoot(
		exec,
		files,
		defaultAPTSnapshotRoot,
		now,
		snapshotID,
	)
}

func newRPMFileSnapshotID(now time.Time) (string, error) {
	randomBytes := make([]byte, 12)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"rpm-%s-%s",
		now.UTC().Format("20060102T150405Z"),
		hex.EncodeToString(randomBytes),
	), nil
}

// RestoreRPMFileSnapshot restores only the repo-file side of an RPM repair snapshot — it
// never runs a package-manager refresh itself (unlike RestoreAPTFileSnapshot's optional
// `apt-get update`), since the caller also needs to prune any newly-imported GPG key
// first; see restoreRPMRepairState in rpm_repair.go for the full rollback sequence.
func RestoreRPMFileSnapshot(exec Executor, snapshot Snapshot, files []string) error {
	return restoreAPTFileSnapshot(exec, snapshot, files, false)
}
