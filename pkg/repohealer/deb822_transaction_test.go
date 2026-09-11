package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyDeb822RepairExecutionAppliesBoundRequest(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"Hit:1 https://download.docker.com/linux/debian bookworm InRelease\n",
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if !got.Attempted {
		t.Fatal("repair was not marked attempted")
	}
	if !got.Applied {
		t.Fatalf("repair was not applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("repair unexpectedly rolled back: %#v", got)
	}
	if got.Error != nil {
		t.Fatalf("repair error = %v", got.Error)
	}
	if !got.Snapshot.Created {
		t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
	}
	if len(exec.commands) != 4 {
		t.Fatalf("command count = %d, want 4", len(exec.commands))
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command did not probe APT locks:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SNAPSHOT_DIR") {
		t.Fatalf("second command did not create a snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], "DEB822_REPAIR_APPLIED|") {
		t.Fatalf("third command did not contain Deb822 mutation marker:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[2], request.SourceFile) {
		t.Fatalf("mutation command missing approved source file:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[2], request.KeyringPath) {
		t.Fatalf("mutation command missing approved keyring path:\n%s", exec.commands[2])
	}
	if !strings.Contains(
		exec.commands[2],
		"RENDERED_SOURCE="+shellQuote(request.RenderedSource),
	) {
		t.Fatalf(
			"mutation command missing quoted rendered Deb822 source binding:\n%s",
			exec.commands[2],
		)
	}
	if !strings.Contains(exec.commands[3], "apt-get update") {
		t.Fatalf("fourth command did not verify with apt-get update:\n%s", exec.commands[3])
	}
}

func TestApplyDeb822RepairExecutionBlocksInvalidRequestBeforeCommands(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	request.SourceFile = "/tmp/docker.sources"

	exec := &fakeExecutor{}
	got := ApplyDeb822RepairExecution(exec, request)

	if !got.Attempted {
		t.Fatal("repair was not marked attempted")
	}
	if got.Applied {
		t.Fatalf("invalid repair was applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("invalid repair unexpectedly rolled back: %#v", got)
	}
	if got.Error == nil {
		t.Fatal("expected blocked request error")
	}
	if !strings.Contains(got.Error.Error(), "outside /etc/apt/sources.list.d") {
		t.Fatalf("error = %q, want unsafe source path rejection", got.Error)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("invalid request ran commands: %#v", exec.commands)
	}
}

func TestApplyDeb822RepairExecutionBlocksOnLockBeforeSnapshot(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		lockProbeOutput: "APT_LOCK_ACTIVE|owners=4321\n",
		lockProbeError:  errors.New("exit status 20"),
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("locked repair was applied: %#v", got)
	}
	if got.Snapshot.Created {
		t.Fatalf("snapshot was created while lock was active: %#v", got.Snapshot)
	}
	if got.RolledBack {
		t.Fatalf("locked repair unexpectedly rolled back: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "package-manager lock is active") {
		t.Fatalf("error = %v, want APT lock rejection", got.Error)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want lock probe only", len(exec.commands))
	}
}

func TestApplyDeb822RepairExecutionFailsBeforeMutationWhenSnapshotFails(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoErrors: []error{
			errors.New("snapshot storage unavailable"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("repair was applied after snapshot failure: %#v", got)
	}
	if got.Snapshot.Created {
		t.Fatalf("snapshot marked created after failure: %#v", got.Snapshot)
	}
	if got.RolledBack {
		t.Fatalf("repair rolled back despite no successful snapshot: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "could not create targeted APT snapshot") {
		t.Fatalf("error = %v, want snapshot failure", got.Error)
	}
	if len(exec.commands) != 2 {
		t.Fatalf("command count = %d, want lock and snapshot only", len(exec.commands))
	}
}

func TestApplyDeb822RepairExecutionRollsBackMutationFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce\n",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("failed repair was applied: %#v", got)
	}
	if !got.Snapshot.Created {
		t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
	}
	if !got.RolledBack {
		t.Fatalf("repair did not roll back after mutation failure: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "fingerprint_mismatch") {
		t.Fatalf("error = %v, want fingerprint mismatch", got.Error)
	}
	if len(exec.commands) != 4 {
		t.Fatalf("command count = %d, want lock, snapshot, mutation, rollback", len(exec.commands))
	}
	if !strings.Contains(exec.commands[3], "sha256sum --strict -c checksums.sha256") {
		t.Fatalf("rollback did not verify snapshot checksums:\n%s", exec.commands[3])
	}
}

func TestApplyDeb822RepairExecutionRollsBackVerificationFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"Err:1 https://download.docker.com/linux/debian bookworm InRelease\nNO_PUBKEY 0000000000000000\n",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 100"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("verification-failed repair was applied: %#v", got)
	}
	if !got.RolledBack {
		t.Fatalf("repair did not roll back after verification failure: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "post-repair Deb822 APT verification failed") {
		t.Fatalf("error = %v, want verification failure", got.Error)
	}
	if len(exec.commands) != 5 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, verification, rollback",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[4], "sha256sum --strict -c checksums.sha256") {
		t.Fatalf("rollback did not verify snapshot checksums:\n%s", exec.commands[4])
	}
}

func TestApplyDeb822RepairExecutionReportsRollbackFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoErrors: []error{
			nil,
			errors.New("snapshot checksum verification failed"),
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce\n",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("failed repair was applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("rollback failure was marked rolled back: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "targeted Deb822 rollback also failed") {
		t.Fatalf("error = %v, want rollback failure", got.Error)
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, rollback",
			len(exec.commands),
		)
	}
}
