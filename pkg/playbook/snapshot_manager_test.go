package playbook

import (
	"errors"
	"os"
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

// snapshotManagerFakeExecutor is a minimal repohealer.Executor fake for exercising the pure
// script-building logic in snapshot_manager.go without a real SSH connection.
type snapshotManagerFakeExecutor struct {
	runOutput     string
	runSudoOutput string
	runSudoErr    error
	lastRunSudo   string
	lastRun       string
	lastLabel     string
}

func (f *snapshotManagerFakeExecutor) Run(command string) (string, error) {
	f.lastRun = command
	return f.runOutput, nil
}

func (f *snapshotManagerFakeExecutor) RunSudo(script string) (string, error) {
	f.lastRunSudo = script
	return f.runSudoOutput, f.runSudoErr
}

func (f *snapshotManagerFakeExecutor) RunSudoWithLabel(script, label string) (string, error) {
	f.lastRunSudo = script
	f.lastLabel = label
	return f.runSudoOutput, f.runSudoErr
}

func TestDiffSnapshotFileAgainstLiveRejectsInvalidSnapshotID(t *testing.T) {
	exec := &snapshotManagerFakeExecutor{}

	_, err := diffSnapshotFileAgainstLive(exec, "not-a-valid-id", "/etc/apt/sources.list.d/hashicorp.list")
	if err == nil {
		t.Fatal("expected an error for an invalid snapshot ID")
	}
	if exec.lastRunSudo != "" {
		t.Fatalf("an invalid snapshot ID must never reach the shell, got: %s", exec.lastRunSudo)
	}
}

func TestDiffSnapshotFileAgainstLiveScriptIsReadOnly(t *testing.T) {
	exec := &snapshotManagerFakeExecutor{runSudoOutput: "--- a\n+++ b\n"}

	_, err := diffSnapshotFileAgainstLive(exec, "apt-20260101T000000Z-abc123", "/etc/apt/sources.list.d/hashicorp.list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	script := exec.lastRunSudo
	if script == "" {
		t.Fatal("expected a script to be run")
	}
	if !strings.Contains(script, "diff -u") {
		t.Fatalf("expected the script to use diff -u, got: %s", script)
	}
	for _, forbidden := range []string{" rm ", " rm\n", ">$LIVE", "> $LIVE", "mv ", "cp "} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("diff script must be read-only, found %q in: %s", forbidden, script)
		}
	}
}

func TestSnapshotManagerDeleteFlowsRequireExplicitYes(t *testing.T) {
	source, err := os.ReadFile("snapshot_manager.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	if got := strings.Count(code, `transfer.ReadRealtimeInput("Type 'yes' to permanently delete these checkpoints, or anything else to cancel: ")`); got < 3 {
		t.Fatalf("expected all three OS delete flows to require an explicit typed yes, found %d", got)
	}
}

func TestSnapshotManagerRestoreRequiresExplicitYes(t *testing.T) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	if got := strings.Count(code, `transfer.ReadRealtimeInput("Type 'yes' to restore this snapshot, or anything else to cancel: ")`); got < 3 {
		t.Fatalf("expected all three OS restore flows to require an explicit typed yes, found %d", got)
	}
}

func TestSnapshotManagerRestoreCreatesSafetySnapshotFirst(t *testing.T) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	for _, marker := range []string{
		"pre-restore-safety-snapshot",
	} {
		if strings.Count(code, marker) < 3 {
			t.Fatalf("expected a pre-restore safety snapshot on all three OS branches (Linux/macOS/Windows), found %d occurrences of %q", strings.Count(code, marker), marker)
		}
	}
}

func TestSnapshotManagerNeverInstallsOrRemovesPackagesAutomatically(t *testing.T) {
	source, err := os.ReadFile("snapshot_manager.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	for _, forbidden := range []string{
		"apt-get install",
		"apt-get remove",
		"dnf install",
		"winget install",
		"choco install",
		"scoop install",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf("snapshot manager must never install or remove a package, found %q", forbidden)
		}
	}
	if !strings.Contains(code, "never installs or removes a package") {
		t.Fatal("expected the menu to state the never-install/remove limitation to the operator")
	}
}

func TestSnapshotManagerRetentionNeverPrunesBelowOne(t *testing.T) {
	// SnapshotIDsToPrune is the single choke point every delete flow uses to decide what to
	// remove; its own unit tests (in pkg/repohealer) already prove it never prunes below one
	// remaining snapshot. This test guards that every delete flow actually routes through it
	// rather than reimplementing retention logic inline.
	source, err := os.ReadFile("snapshot_manager.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	if got := strings.Count(code, "repohealer.SnapshotIDsToPrune("); got < 3 {
		t.Fatalf("expected all three OS delete flows to use repohealer.SnapshotIDsToPrune, found %d calls", got)
	}
}

func TestSnapshotManagerFakeExecutorSatisfiesInterface(t *testing.T) {
	var _ repohealer.Executor = &snapshotManagerFakeExecutor{}
	var _ error = errors.New("sanity")
}
