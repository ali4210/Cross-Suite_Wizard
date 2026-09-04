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

	if !strings.Contains(command, `! -path "$SNAPSHOT_DIR/checksums.sha256"`) {
		t.Fatalf(
			"snapshot checksum command must exclude its own manifest:\n%s",
			command,
		)
	}

	for _, expected := range []string{
		"SUDO:",
		`TARGETS=("/etc/apt/sources.list.d/docker.list" "/etc/apt/keyrings/docker.gpg")`,
		`if [ -e "$target" ]; then`,
		`printf 'present\n' > "$metadata"`,
		`cp -a "$target" "$content"`,
		`printf 'absent\n' > "$metadata"`,
		`checksums.sha256`,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("snapshot command missing %q:\n%s", expected, command)
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
		`if [ ! -f "$metadata" ]; then`,
		`ROLLBACK_ERROR|missing_snapshot_metadata|$target`,
		`if [ "$state" = "present" ]; then`,
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
