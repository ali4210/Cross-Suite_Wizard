package repohealer

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestApproveAndApplyHashiCorpAPTListRepairDeclinedWithoutExplicitYes(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "true")
	preflight := readyHashiCorpAPTListRepairPreflight(t)
	exec := &fakeExecutor{}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "no")

	if got.Status != HashiCorpAPTListRepairApprovalStatusDeclined {
		t.Fatalf("status = %q, want declined", got.Status)
	}
	if got.ApplyResult.Attempted {
		t.Fatal("a decline must never attempt an apply")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a decline must not execute any command, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairBlockedWhenOperatorPolicyDisabled(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "false")
	preflight := readyHashiCorpAPTListRepairPreflight(t)
	exec := &fakeExecutor{}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "yes")

	if got.Status != HashiCorpAPTListRepairApprovalStatusBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(got.Reason, "CROSS_SUITE_APTLIST_REPAIR_ENABLED") {
		t.Fatalf("reason should name the operator-policy env var, got: %s", got.Reason)
	}
	if got.ApplyResult.Attempted {
		t.Fatal("a disabled operator policy must never attempt an apply")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a disabled operator policy must not execute any command, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairBlockedWhenPreflightNotReady(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "true")
	preflight := HashiCorpAPTListRepairPreflight{
		Ready:  false,
		Reason: "required tool \"gpg\" is unavailable",
	}
	exec := &fakeExecutor{}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "yes")

	if got.Status != HashiCorpAPTListRepairApprovalStatusBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(got.Reason, "preflight is not ready") {
		t.Fatalf("reason should explain the preflight failure, got: %s", got.Reason)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a not-ready preflight must not execute any command, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairBlockedOnSafetyGate(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "true")
	preflight := readyHashiCorpAPTListRepairPreflight(t)
	exec := &fakeExecutor{
		runOutputs:     []string{diskFullNetworkFactsProbeOutput()},
		runSudoOutputs: []string{""},
	}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "yes")

	if got.Status != HashiCorpAPTListRepairApprovalStatusBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(strings.ToLower(got.Reason), "disk") {
		t.Fatalf("reason should explain the disk space block, got: %s", got.Reason)
	}
	if got.ApplyResult.Attempted {
		t.Fatal("a safety-gate block must never attempt an apply")
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairAppliesWhenFullyApproved(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "true")
	preflight := readyHashiCorpAPTListRepairPreflight(t)
	exec := &fakeExecutor{
		runOutputs: []string{safeNetworkFactsProbeOutput()},
		// First RunSudo call is the safety gate's dpkg --audit probe (healthy/empty);
		// the second is the apply step's targeted snapshot creation.
		runSudoOutputs: []string{"", ""},
		runSudoLabelOutputs: []string{
			"APTLIST_REPAIR_APPLIED|hashicorp|fingerprint=" + HashiCorpAPTListExpectedFingerprint,
			"",
		},
	}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "yes")

	if got.Status != HashiCorpAPTListRepairApprovalStatusApplied {
		t.Fatalf("status = %q, want applied (reason: %s)", got.Status, got.Reason)
	}
	if !got.ApplyResult.Applied {
		t.Fatalf("expected the underlying apply to report success: %v", got.ApplyResult.Error)
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairFailsAndClassifiesRollback(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairExecutionEnabledEnv, "true")
	preflight := readyHashiCorpAPTListRepairPreflight(t)
	exec := &fakeExecutor{
		runOutputs: []string{safeNetworkFactsProbeOutput()},
		// safety dpkg probe (healthy), snapshot create, rollback restore.
		runSudoOutputs: []string{"", "", ""},
		runSudoLabelOutputs: []string{
			"APTLIST_REPAIR_ERROR|fingerprint_mismatch|profile=hashicorp",
		},
	}
	exec.runSudoLabelErrors = []error{
		errors.New("exit status 22"),
	}

	got := ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, "y")

	if got.Status != HashiCorpAPTListRepairApprovalStatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.ApplyResult.RolledBack {
		t.Fatal("a failed apply must have been rolled back")
	}

	audit := BuildHashiCorpAPTListRepairAuditEvent(got, time.Now())
	if audit.FailureCategory != RepairFailureFingerprint {
		t.Fatalf("failure category = %q, want fingerprint_mismatch", audit.FailureCategory)
	}
}
