package repohealer

import (
	"errors"
	"strings"
	"testing"
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
		`install -d -m 0700 "$SNAPSHOT_DIR/files"`,
		`chmod 0600 "$SNAPSHOT_DIR/manifest.txt"`,
		`if [ -e "$target" ]; then`,
		`printf 'present\n' > "$metadata"`,
		`cp -a "$target" "$content"`,
		`printf 'absent\n' > "$metadata"`,
		`sha256sum "$SNAPSHOT_DIR/manifest.txt"`,
		`find "$SNAPSHOT_DIR/files" -type f -print0`,
		`> "$SNAPSHOT_DIR/checksums.sha256"`,
		`chmod 0600 "$SNAPSHOT_DIR/checksums.sha256"`,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("snapshot command missing %q:\n%s", expected, command)
		}
	}

	if strings.Contains(command, `find "$SNAPSHOT_DIR" -type f`) {
		t.Fatalf(
			"snapshot checksum collection must be limited to manifest and payload files, not all snapshot files:\n%s",
			command,
		)
	}

	if strings.Contains(command, `! -path "$SNAPSHOT_DIR/checksums.sha256"`) {
		t.Fatalf(
			"snapshot implementation should not recursively walk the snapshot root:\n%s",
			command,
		)
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
		`test -f "$SNAPSHOT_DIR/checksums.sha256"`,
		`sha256sum --strict -c checksums.sha256`,
		`ROLLBACK_ERROR|snapshot_checksum_verification_failed`,
		`if [ ! -f "$metadata" ]; then`,
		`ROLLBACK_ERROR|missing_snapshot_metadata|$target`,
		`if [ "$state" = "present" ]; then`,
		`if [ ! -f "$content" ]; then`,
		`ROLLBACK_ERROR|missing_snapshot_content|$target`,
		`exit 33`,
		`mkdir -p "$(dirname "$target")"`,
		`cp -a "$content" "$target"`,
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
