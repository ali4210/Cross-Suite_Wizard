package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestCreateHomebrewSnapshotRunsOverNonSudoChannel(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{"Writing Brewfile to ...\n"}}

	snapshot, err := CreateHomebrewSnapshot(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !snapshot.Created {
		t.Fatal("expected snapshot to be created")
	}
	if !strings.HasPrefix(snapshot.ID, "brew-") {
		t.Fatalf("expected snapshot ID to start with brew-, got %q", snapshot.ID)
	}
	if !strings.HasSuffix(snapshot.Path, "/Brewfile") {
		t.Fatalf("expected snapshot path to end with /Brewfile, got %q", snapshot.Path)
	}
	if len(exec.commands) != 1 || !strings.HasPrefix(exec.commands[0], "RUN:") {
		t.Fatalf("expected a single non-sudo Run call, got %v", exec.commands)
	}
}

func TestCreateHomebrewSnapshotFailsCleanlyOnError(t *testing.T) {
	exec := &fakeExecutor{runErrors: []error{errors.New("brew: command not found")}}

	snapshot, err := CreateHomebrewSnapshot(exec)
	if err == nil {
		t.Fatal("expected an error")
	}
	if snapshot.Created {
		t.Fatal("snapshot must not be marked created on failure")
	}
}

func TestRestoreHomebrewSnapshotRejectsInvalidID(t *testing.T) {
	exec := &fakeExecutor{}

	err := RestoreHomebrewSnapshot(exec, Snapshot{ID: "../../etc/passwd", Path: "/tmp/Brewfile", Created: true})
	if err == nil {
		t.Fatal("expected an error for a malformed snapshot id")
	}
}

func TestRestoreHomebrewSnapshotRejectsUncreatedSnapshot(t *testing.T) {
	exec := &fakeExecutor{}

	err := RestoreHomebrewSnapshot(exec, Snapshot{Created: false})
	if err == nil {
		t.Fatal("expected an error for a snapshot that was never created")
	}
}

func TestListHomebrewSnapshotsParsesAndSortsNewestFirst(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"SNAPSHOT|brew-20240101T000000Z-aa|/home/u/.cross-suite/homebrew-snapshots/brew-20240101T000000Z-aa/Brewfile\n" +
				"SNAPSHOT|brew-20240601T000000Z-bb|/home/u/.cross-suite/homebrew-snapshots/brew-20240601T000000Z-bb/Brewfile\n",
		},
	}

	snapshots, err := ListHomebrewSnapshots(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}
	if snapshots[0].ID != "brew-20240601T000000Z-bb" {
		t.Fatalf("expected newest snapshot first, got %q", snapshots[0].ID)
	}
}

func TestListHomebrewSnapshotsRejectsMalformedID(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{"SNAPSHOT|../../etc/passwd|/tmp/Brewfile\n"},
	}

	snapshots, err := ListHomebrewSnapshots(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("expected malformed snapshot id to be dropped, got %+v", snapshots)
	}
}

// Confirms applyGenericRepairAction routes a UseHomebrewSnapshot action through
// CreateHomebrewSnapshot/RestoreHomebrewSnapshot (non-sudo channel) instead of the
// file-based APT snapshot path, and that a verification failure rolls back via
// `brew bundle install` against the just-created snapshot.
func TestApplyGenericRepairActionUsesHomebrewSnapshotOnVerificationFailure(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"Writing Brewfile to ...\n", // CreateHomebrewSnapshot
			"cleaned\n",                 // Commands[0]: brew cleanup -s
			// Verification[0]: brew doctor
		},
		runErrors: []error{
			nil,                         // snapshot create
			nil,                         // command
			errors.New("doctor failed"), // verification fails
			nil,                         // RestoreHomebrewSnapshot (rollback)
		},
	}

	action := RepairAction{
		ID:                  "brew-cleanup-cache",
		Eligible:            true,
		RequiresConsent:     true,
		Commands:            []string{"brew cleanup -s"},
		Verification:        []string{"brew doctor"},
		RunAsNonRoot:        true,
		UseHomebrewSnapshot: true,
	}

	got := ApproveAndApplyGenericRepair(exec, []RepairAction{action}, action.ID, "yes")

	if got.RepairResult.Applied {
		t.Fatal("repair must not be marked applied when verification fails")
	}
	if !got.RepairResult.RolledBack {
		t.Fatal("expected Homebrew snapshot rollback to run on verification failure")
	}
	if !strings.HasPrefix(got.RepairResult.Snapshot.ID, "brew-") {
		t.Fatalf("expected a Homebrew snapshot to have been created, got %+v", got.RepairResult.Snapshot)
	}
	for _, cmd := range exec.commands {
		if strings.HasPrefix(cmd, "SUDO") {
			t.Fatalf("Homebrew actions must never go through the sudo channel, got %v", exec.commands)
		}
	}
}
