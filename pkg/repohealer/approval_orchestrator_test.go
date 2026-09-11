package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestApproveAndApplyAPTRepairExecutesApprovedDockerAction(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
		},
	}

	got := ApproveAndApplyAPTRepair(
		exec,
		dockerRepairResult(),
		"apt-keyring-repair-docker-ce",
		"yes",
	)

	if got.Decision != ApprovalExecutionExecuted {
		t.Fatalf("decision = %q, want %q; error = %v", got.Decision, ApprovalExecutionExecuted, got.Error)
	}
	if !got.RepairResult.Attempted {
		t.Fatal("approved Docker action must attempt repair")
	}
	if !got.RepairResult.Applied {
		t.Fatalf("approved Docker action must apply successfully: %v", got.Error)
	}
	if got.RepairResult.RolledBack {
		t.Fatal("successful approved Docker action must not roll back")
	}
	if got.Action.ProfileID != "docker-ce" {
		t.Fatalf("selected profile ID = %q, want docker-ce", got.Action.ProfileID)
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, verification commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create the targeted snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], `PROFILE_ID="docker-ce"`) {
		t.Fatalf("third command must apply the Docker repair:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "apt-get update") {
		t.Fatalf("fourth command must verify APT health:\n%s", exec.commands[3])
	}
}

func TestApproveAndApplyAPTRepairRejectsDeclinedActionWithoutCommands(t *testing.T) {
	exec := &fakeExecutor{}

	got := ApproveAndApplyAPTRepair(
		exec,
		dockerRepairResult(),
		"apt-keyring-repair-docker-ce",
		"no",
	)

	if got.Decision != ApprovalExecutionDeclined {
		t.Fatalf("decision = %q, want %q", got.Decision, ApprovalExecutionDeclined)
	}
	if got.Error == nil {
		t.Fatal("declined action must return an error")
	}
	if got.RepairResult.Attempted {
		t.Fatal("declined action must not attempt repair")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("declined action must not execute commands; got %d", len(exec.commands))
	}
}

func TestApproveAndApplyAPTRepairRejectsBlockedActionWithoutCommands(t *testing.T) {
	exec := &fakeExecutor{}

	result := dockerRepairResult()
	result.Target.Codename = "unsupported-release"

	got := ApproveAndApplyAPTRepair(
		exec,
		result,
		"apt-keyring-repair-docker-ce",
		"yes",
	)

	if got.Decision != ApprovalExecutionBlocked {
		t.Fatalf("decision = %q, want %q", got.Decision, ApprovalExecutionBlocked)
	}
	if got.Error == nil {
		t.Fatal("blocked action must return an error")
	}
	if got.RepairResult.Attempted {
		t.Fatal("blocked action must not attempt repair")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("blocked action must not execute commands; got %d", len(exec.commands))
	}
}

func TestApproveAndApplyAPTRepairRejectsUnknownActionWithoutCommands(t *testing.T) {
	exec := &fakeExecutor{}

	got := ApproveAndApplyAPTRepair(
		exec,
		dockerRepairResult(),
		"apt-keyring-repair-not-real",
		"yes",
	)

	if got.Decision != ApprovalExecutionActionNotFound {
		t.Fatalf("decision = %q, want %q", got.Decision, ApprovalExecutionActionNotFound)
	}
	if got.Error == nil {
		t.Fatal("unknown action must return an error")
	}
	if got.RepairResult.Attempted {
		t.Fatal("unknown action must not attempt repair")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unknown action must not execute commands; got %d", len(exec.commands))
	}
}

func TestApproveAndApplyAPTRepairReturnsExecutionFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApproveAndApplyAPTRepair(
		exec,
		dockerRepairResult(),
		"apt-keyring-repair-docker-ce",
		"y",
	)

	if got.Decision != ApprovalExecutionExecuted {
		t.Fatalf("decision = %q, want %q", got.Decision, ApprovalExecutionExecuted)
	}
	if !got.RepairResult.Attempted {
		t.Fatal("approved action must attempt repair")
	}
	if got.RepairResult.Applied {
		t.Fatal("fingerprint mismatch must not apply repair")
	}
	if !got.RepairResult.RolledBack {
		t.Fatal("fingerprint mismatch must roll back")
	}
	if got.Error == nil {
		t.Fatal("execution failure must return an error")
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, rollback commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create the targeted snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], `PROFILE_ID="docker-ce"`) {
		t.Fatalf("third command must apply the Docker repair:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "SUDO:") {
		t.Fatalf("fourth command must perform targeted rollback:\n%s", exec.commands[3])
	}
}

func TestApproveAndApplyAPTRepairExecutesApprovedDockerBindingMismatch(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
		},
	}

	result := dockerRepairResult()
	result.Findings[0].Code = "APT_SOURCE_KEYRING_MISMATCH"

	got := ApproveAndApplyAPTRepair(
		exec,
		result,
		"apt-source-binding-repair-docker-ce",
		"yes",
	)

	if got.Decision != ApprovalExecutionExecuted {
		t.Fatalf(
			"decision = %q, want %q; error = %v",
			got.Decision,
			ApprovalExecutionExecuted,
			got.Error,
		)
	}
	if got.Action.FindingCode != "APT_SOURCE_KEYRING_MISMATCH" {
		t.Fatalf("finding code = %q", got.Action.FindingCode)
	}
	if !got.RepairResult.Attempted {
		t.Fatal("approved Docker binding mismatch must attempt repair")
	}
	if !got.RepairResult.Applied {
		t.Fatalf("approved Docker binding mismatch must apply: %v", got.Error)
	}
	if got.RepairResult.RolledBack {
		t.Fatal("successful Docker binding mismatch repair must not roll back")
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, verification commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create the targeted snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], `PROFILE_ID="docker-ce"`) {
		t.Fatalf("third command must apply the Docker repair:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "apt-get update") {
		t.Fatalf("fourth command must verify APT health:\n%s", exec.commands[3])
	}
}
