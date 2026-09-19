package repohealer

import (
	"strings"
	"testing"
)

func TestApproveAndApplyHashiCorpAPTListRepairBlocksWhenPolicyDisabled(
	t *testing.T,
) {
	t.Setenv("CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED", "")

	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	preflight := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		readyHashiCorpAPTListRepairPreflightProbe(),
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	got := ApproveAndApplyHashiCorpAPTListRepair(
		hashicorpAPTListRepairExecutionPanicExecutor{},
		request,
		preflight,
	)

	if got.Status != HashiCorpAPTListRepairApprovalBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if got.Execution.Attempted {
		t.Fatal("attempted = true, want false")
	}
	if got.Execution.Applied {
		t.Fatal("applied = true, want false")
	}
	if got.Execution.RolledBack {
		t.Fatal("rolledBack = true, want false")
	}
	if got.Reason == "" {
		t.Fatal("reason is empty, want policy block reason")
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairAppliesBoundReadyRequest(
	t *testing.T,
) {
	t.Setenv("CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED", "true")

	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	preflight := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		readyHashiCorpAPTListRepairPreflightProbe(),
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	exec := &hashiCorpAPTListRepairExecutionPublicFakeExecutor{
		probeOutput: readyHashiCorpAPTListRepairPreflightProbeOutputWithPresentKeyring(),
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
					request.ExpectedFingerprint,
			},
			{
				output: "Hit:1 https://apt.releases.hashicorp.com bookworm InRelease\n" +
					"HASHICORP_APT_LIST_REPAIR_VERIFIED|host=apt.releases.hashicorp.com|exit=0",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
		},
	}

	got := ApproveAndApplyHashiCorpAPTListRepair(
		exec,
		request,
		preflight,
	)

	if got.Status != HashiCorpAPTListRepairApprovalApplied {
		t.Fatalf("status = %q, want applied", got.Status)
	}
	if !got.Execution.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if !got.Execution.Applied {
		t.Fatal("applied = false, want true")
	}
	if got.Execution.RolledBack {
		t.Fatal("rolledBack = true, want false")
	}
	if got.Reason != "" {
		t.Fatalf("reason = %q, want empty", got.Reason)
	}
	if exec.probeCalls != 1 {
		t.Fatalf("fresh probe calls = %d, want 1", exec.probeCalls)
	}
	if exec.labeledCalls != 2 {
		t.Fatalf(
			"labeled calls = %d, want 2 (mutation + verification)",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 1 {
		t.Fatalf(
			"sudo calls = %d, want 1 (snapshot only)",
			exec.sudoCalls,
		)
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairBlocksMismatchedPreflightWithoutExecution(
	t *testing.T,
) {
	t.Setenv("CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED", "true")

	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	mismatched := request
	mismatched.SourceLine++

	got := ApproveAndApplyHashiCorpAPTListRepair(
		hashicorpAPTListRepairExecutionPanicExecutor{},
		request,
		HashiCorpAPTListRepairPreflight{
			Request: mismatched,
			Ready:   true,
		},
	)

	if got.Status != HashiCorpAPTListRepairApprovalBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if got.Execution.Attempted {
		t.Fatal("attempted = true, want false")
	}
	if !strings.Contains(
		strings.ToLower(got.Reason),
		"does not match",
	) {
		t.Fatalf("reason = %q, want binding failure", got.Reason)
	}
}

func TestApproveAndApplyHashiCorpAPTListRepairPreservesRollbackFailure(
	t *testing.T,
) {
	t.Setenv("CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED", "true")

	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	preflight := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		readyHashiCorpAPTListRepairPreflightProbe(),
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	exec := &hashiCorpAPTListRepairExecutionPublicFakeExecutor{
		probeOutput: readyHashiCorpAPTListRepairPreflightProbeOutputWithPresentKeyring(),
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
					request.ExpectedFingerprint,
			},
			{
				output: "W: GPG error: https://apt.releases.hashicorp.com bookworm InRelease: NO_PUBKEY FC9CA96ACA026560\n" +
					"W: Failed to fetch https://apt.releases.hashicorp.com/dists/bookworm/InRelease",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
			{},
		},
	}

	got := ApproveAndApplyHashiCorpAPTListRepair(
		exec,
		request,
		preflight,
	)

	if got.Status != HashiCorpAPTListRepairApprovalFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.Execution.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if got.Execution.Applied {
		t.Fatal("applied = true, want false")
	}
	if !got.Execution.RolledBack {
		t.Fatal("rolledBack = false, want true")
	}
	if !strings.Contains(strings.ToLower(got.Reason), "verification") {
		t.Fatalf("reason = %q, want verification failure", got.Reason)
	}
	if !strings.Contains(got.Execution.VerificationOut, "NO_PUBKEY") {
		t.Fatalf(
			"verification output = %q, want NO_PUBKEY diagnostics",
			got.Execution.VerificationOut,
		)
	}
	if exec.probeCalls != 1 {
		t.Fatalf("fresh probe calls = %d, want 1", exec.probeCalls)
	}
	if exec.labeledCalls != 2 {
		t.Fatalf(
			"labeled calls = %d, want 2 (mutation + verification)",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 2 {
		t.Fatalf(
			"sudo calls = %d, want 2 (snapshot + rollback)",
			exec.sudoCalls,
		)
	}
}
