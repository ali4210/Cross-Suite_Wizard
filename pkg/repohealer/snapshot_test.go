package repohealer

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCreateAPTFileSnapshotRecordsPresentAndAbsentStates(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
	}

	files := []string{
		"/etc/apt/sources.list.d/docker.list",
		"/etc/apt/keyrings/docker.gpg",
	}

	snapshot, err := CreateAPTFileSnapshot(exec, files)

	if err != nil {
		t.Fatalf("CreateAPTFileSnapshot() error = %v", err)
	}
	if !snapshot.Created {
		t.Fatal("expected created snapshot")
	}
	if snapshot.ID == "" {
		t.Fatal("expected snapshot ID")
	}
	if snapshot.Path == "" {
		t.Fatal("expected snapshot path")
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected one snapshot command, got %d", len(exec.commands))
	}

	command := exec.commands[0]

	for _, expected := range []string{
		"SUDO:",
		`TARGETS=("/etc/apt/sources.list.d/docker.list" "/etc/apt/keyrings/docker.gpg")`,
		`install -d -m 0700 "$SNAPSHOT_ROOT"`,
		`mkdir -m 0700 "$SNAPSHOT_DIR"`,
		`install -d -m 0700 "$SNAPSHOT_DIR/files"`,
		`chmod 0600 "$SNAPSHOT_DIR/manifest.txt"`,
		`if [ -e "$target" ]; then`,
		`printf 'present\n' > "$metadata"`,
		`stat -c '%a' "$target" >> "$metadata"`,
		`cp -a "$target" "$content"`,
		`printf 'absent\n' > "$metadata"`,
		`sha256sum manifest.txt`,
		`find files -type f -print0`,
		`> "$SNAPSHOT_DIR/checksums.sha256"`,
		`chmod 0600 "$SNAPSHOT_DIR/checksums.sha256"`,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("snapshot command missing %q:\n%s", expected, command)
		}
	}

	for _, unexpected := range []string{
		`find "$SNAPSHOT_DIR" -type f`,
		`! -path "$SNAPSHOT_DIR/checksums.sha256"`,
		`sha256sum "$SNAPSHOT_DIR/manifest.txt"`,
		`find "$SNAPSHOT_DIR/files" -type f -print0`,
	} {
		if strings.Contains(command, unexpected) {
			t.Fatalf("snapshot command must not contain %q:\n%s", unexpected, command)
		}
	}
}

func TestCreateAPTFileSnapshotReturnsUncreatedSnapshotOnFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoErrors: []error{
			errors.New("snapshot command failed"),
		},
	}

	snapshot, err := CreateAPTFileSnapshot(
		exec,
		[]string{"/etc/apt/keyrings/docker.gpg"},
	)

	if err == nil {
		t.Fatal("expected snapshot error")
	}
	if snapshot.Created {
		t.Fatal("failed snapshot must not be marked created")
	}
	if snapshot.ID == "" {
		t.Fatal("failed snapshot should retain generated ID for diagnostics")
	}
	if snapshot.Path == "" {
		t.Fatal("failed snapshot should retain generated path for diagnostics")
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected one attempted snapshot command, got %d", len(exec.commands))
	}
}

func TestRestoreAPTFileSnapshotVerifiesChecksumsBeforeRestoring(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
	}

	snapshot := Snapshot{
		ID:      "apt-test",
		Path:    "/var/lib/cross-suite/snapshots/apt-test",
		Created: true,
	}

	err := RestoreAPTFileSnapshot(
		exec,
		snapshot,
		[]string{"/etc/apt/sources.list.d/docker.list"},
	)
	if err != nil {
		t.Fatalf("RestoreAPTFileSnapshot() error = %v", err)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected one rollback command, got %d", len(exec.commands))
	}

	command := exec.commands[0]

	checkAt := strings.Index(command, `sha256sum --strict -c checksums.sha256`)
	copyAt := strings.Index(command, `cp -a "$content" "$target"`)

	if checkAt < 0 {
		t.Fatalf("rollback must validate snapshot checksums:\n%s", command)
	}
	if copyAt < 0 {
		t.Fatalf("rollback must include snapshot-content restoration:\n%s", command)
	}
	if checkAt > copyAt {
		t.Fatalf("checksum verification must occur before restoration:\n%s", command)
	}

	for _, expected := range []string{
		"SUDO:",
		`test -d "$SNAPSHOT_DIR/files"`,
		`test -f "$SNAPSHOT_DIR/manifest.txt"`,
		`test -f "$SNAPSHOT_DIR/checksums.sha256"`,
		`ROLLBACK_ERROR|snapshot_checksum_verification_failed`,
		`exit 30`,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("rollback integrity gate missing %q:\n%s", expected, command)
		}
	}
}

func TestRestoreAPTFileSnapshotRestoresPresentAndRemovesAbsentPaths(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
	}

	snapshot := Snapshot{
		ID:      "apt-test",
		Path:    "/var/lib/cross-suite/snapshots/apt-test",
		Created: true,
	}

	files := []string{
		"/etc/apt/sources.list.d/docker.list",
		"/etc/apt/keyrings/docker.gpg",
	}

	err := RestoreAPTFileSnapshot(exec, snapshot, files)

	if err != nil {
		t.Fatalf("RestoreAPTFileSnapshot() error = %v", err)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected one rollback command, got %d", len(exec.commands))
	}

	command := exec.commands[0]

	for _, expected := range []string{
		"SUDO:",
		`test -d "$SNAPSHOT_DIR/files"`,
		`test -f "$SNAPSHOT_DIR/manifest.txt"`,
		`test -f "$SNAPSHOT_DIR/checksums.sha256"`,
		`sha256sum --strict -c checksums.sha256`,
		`ROLLBACK_ERROR|snapshot_checksum_verification_failed`,
		`if [ ! -f "$metadata" ]; then`,
		`ROLLBACK_ERROR|missing_snapshot_metadata|$target`,
		`if [ "$state" = "present" ]; then`,
		`mode="$(sed -n '2p' "$metadata")"`,
		`grep -Eq '^[0-7]{3,4}$'`,
		`ROLLBACK_ERROR|invalid_snapshot_mode|$target|$mode`,
		`exit 34`,
		`if [ ! -f "$content" ]; then`,
		`ROLLBACK_ERROR|missing_snapshot_content|$target`,
		`exit 33`,
		`mkdir -p "$(dirname "$target")"`,
		`cp -a "$content" "$target"`,
		`chmod "$mode" "$target"`,
		`elif [ "$state" = "absent" ]; then`,
		`rm -f "$target"`,
		`ROLLBACK_ERROR|invalid_snapshot_state|$target|$state`,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("rollback command missing %q:\n%s", expected, command)
		}
	}
}

func TestRestoreAPTFileSnapshotRejectsInvalidSnapshot(t *testing.T) {
	exec := &fakeExecutor{}

	err := RestoreAPTFileSnapshot(
		exec,
		Snapshot{
			ID:      "apt-invalid",
			Path:    "",
			Created: false,
		},
		[]string{"/etc/apt/keyrings/docker.gpg"},
	)

	if err == nil {
		t.Fatal("expected invalid snapshot error")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("invalid snapshot must not execute commands; got %d", len(exec.commands))
	}
}

func TestNewAPTFileSnapshotIDProducesDistinctIDsAtSameTime(t *testing.T) {
	now := time.Date(2026, time.September, 12, 1, 4, 0, 0, time.UTC)

	first, err := newAPTFileSnapshotID(now)
	if err != nil {
		t.Fatalf("newAPTFileSnapshotID() first error = %v", err)
	}

	second, err := newAPTFileSnapshotID(now)
	if err != nil {
		t.Fatalf("newAPTFileSnapshotID() second error = %v", err)
	}

	if first == second {
		t.Fatalf("snapshot IDs must be unique, both were %q", first)
	}

	for _, id := range []string{first, second} {
		if !strings.HasPrefix(id, "apt-20260912T010400Z-") {
			t.Fatalf("snapshot ID %q has unexpected timestamp prefix", id)
		}
		if strings.Contains(id, "/") || strings.Contains(id, "\\") {
			t.Fatalf("snapshot ID %q must not contain path separators", id)
		}
	}
}

func TestCreateAPTFileSnapshotAtRootRejectsInvalidIDWithoutCommands(t *testing.T) {
	now := time.Date(2026, time.September, 12, 1, 4, 1, 0, time.UTC)

	for _, snapshotID := range []string{
		"",
		".",
		"..",
		"not-an-apt-snapshot",
		"apt-../escape",
		"apt-test/child",
		`apt-test\child`,
	} {
		t.Run(snapshotID, func(t *testing.T) {
			exec := &fakeExecutor{}

			snapshot, err := createAPTFileSnapshotAtRoot(
				exec,
				[]string{"/etc/apt/keyrings/docker.gpg"},
				"/var/lib/cross-suite/snapshots",
				now,
				snapshotID,
			)

			if err == nil {
				t.Fatalf("invalid snapshot ID %q unexpectedly succeeded", snapshotID)
			}
			if snapshot.Created {
				t.Fatalf(
					"invalid snapshot ID %q must not create a snapshot",
					snapshotID,
				)
			}
			if len(exec.commands) != 0 {
				t.Fatalf(
					"invalid snapshot ID %q must not execute commands: %v",
					snapshotID,
					exec.commands,
				)
			}
		})
	}
}

func TestCreateAPTFileSnapshotAtRootReturnsUncreatedSnapshotOnCollision(t *testing.T) {
	exec := &fakeExecutor{
		runSudoErrors: []error{
			errors.New("mkdir: cannot create directory: File exists"),
		},
	}

	now := time.Date(2026, time.September, 12, 1, 4, 2, 0, time.UTC)
	snapshot, err := createAPTFileSnapshotAtRoot(
		exec,
		[]string{"/etc/apt/keyrings/docker.gpg"},
		"/var/lib/cross-suite/snapshots",
		now,
		"apt-collision-test",
	)

	if err == nil {
		t.Fatal("snapshot collision must return an error")
	}
	if snapshot.Created {
		t.Fatal("collision must not return a created snapshot")
	}
	if snapshot.ID != "apt-collision-test" {
		t.Fatalf("snapshot ID = %q", snapshot.ID)
	}
	if snapshot.Path != "/var/lib/cross-suite/snapshots/apt-collision-test" {
		t.Fatalf("snapshot path = %q", snapshot.Path)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("collision must attempt exactly one command, got %d", len(exec.commands))
	}
	if !strings.Contains(exec.commands[0], `mkdir -m 0700 "$SNAPSHOT_DIR"`) {
		t.Fatalf(
			"collision-safe snapshot command must use non-idempotent mkdir:\n%s",
			exec.commands[0],
		)
	}
	if strings.Contains(exec.commands[0], `install -d -m 0700 "$SNAPSHOT_DIR"`) {
		t.Fatalf(
			"snapshot command must not use idempotent parent directory creation:\n%s",
			exec.commands[0],
		)
	}
}
