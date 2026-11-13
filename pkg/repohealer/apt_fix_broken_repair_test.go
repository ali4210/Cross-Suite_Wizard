package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildAPTFixBrokenPreviewNothingToRepair(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
	}

	got, err := BuildAPTFixBrokenPreview(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.NothingToRepair {
		t.Fatal("expected NothingToRepair when dpkg --audit is empty")
	}
	if got.Ready {
		t.Fatal("a clean dpkg --audit must not be reported as ready to repair")
	}
}

func TestBuildAPTFixBrokenPreviewReadyShowsRealAuditAndSimulation(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{"foo is missing files"},
		runSudoLabelOutputs: []string{
			"The following packages will be REMOVED:\n  foo\n0 upgraded, 0 newly installed, 1 to remove",
		},
	}

	got, err := BuildAPTFixBrokenPreview(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Ready {
		t.Fatalf("expected ready preview, reason: %s", got.Reason)
	}
	if !strings.Contains(got.DpkgAuditOutput, "foo is missing files") {
		t.Fatalf("expected real dpkg --audit output, got: %s", got.DpkgAuditOutput)
	}
	if !strings.Contains(got.SimulatedPlan, "to remove") {
		t.Fatalf("expected real simulated plan, got: %s", got.SimulatedPlan)
	}
	if len(exec.commands) != 2 {
		t.Fatalf("preview must only run the audit probe and the simulation, got %d commands", len(exec.commands))
	}
	for _, forbidden := range []string{"-y ", "--yes"} {
		for _, command := range exec.commands {
			if strings.Contains(command, forbidden) {
				t.Fatalf("preview must never pass a non-interactive apply flag, found %q in: %s", forbidden, command)
			}
		}
	}
}

func readyAPTFixBrokenPreview() APTFixBrokenPreview {
	return APTFixBrokenPreview{
		Ready:           true,
		DpkgAuditOutput: "foo is missing files",
		SimulatedPlan:   "0 upgraded, 0 newly installed, 1 to remove",
	}
}

func TestApplyAPTFixBrokenRepairAppliesSuccessfully(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
		runSudoLabelOutputs: []string{
			"0 upgraded, 0 newly installed, 1 removed",
			"",
			"",
		},
	}

	got := ApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview())

	if !got.Applied {
		t.Fatalf("expected apply to succeed: %v", got.Error)
	}
	if got.RolledBack {
		t.Fatal("a successful apply must not roll back")
	}
	if !got.Snapshot.Created {
		t.Fatal("expected a created dpkg-database snapshot before applying")
	}
}

func TestApplyAPTFixBrokenRepairRollsBackWhenStillBrokenAfterward(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{"", ""},
		runSudoLabelOutputs: []string{
			"0 upgraded, 0 newly installed, 1 removed",
			"bar is still half-installed",
		},
	}

	got := ApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview())

	if got.Applied {
		t.Fatal("must not be applied if dpkg --audit is still broken afterward")
	}
	if !got.RolledBack {
		t.Fatal("expected an automatic rollback")
	}
	if !strings.Contains(got.Error.Error(), "bar is still half-installed") {
		t.Fatalf("expected the remaining audit output in the error, got: %v", got.Error)
	}
}

func TestApplyAPTFixBrokenRepairRollsBackOnCommandFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs:      []string{"", ""},
		runSudoLabelOutputs: []string{"E: Unable to correct problems"},
		runSudoLabelErrors:  []error{errors.New("exit status 100")},
	}

	got := ApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview())

	if got.Applied {
		t.Fatal("a failing apt-get command must never be applied")
	}
	if !got.RolledBack {
		t.Fatal("expected an automatic rollback")
	}
}

func TestApplyAPTFixBrokenRepairBlockedWhenPreviewNotReady(t *testing.T) {
	exec := &fakeExecutor{}

	got := ApplyAPTFixBrokenRepair(exec, APTFixBrokenPreview{Ready: false, Reason: "nothing to repair"})

	if got.Applied || got.RolledBack {
		t.Fatal("a not-ready preview must never apply or roll back")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a not-ready preview must not execute any command, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyAPTFixBrokenRepairRequiresExactPhraseNotBareYes(t *testing.T) {
	t.Setenv(APTFixBrokenRepairExecutionEnabledEnv, "true")

	got := ApproveAndApplyAPTFixBrokenRepair(&fakeExecutor{}, readyAPTFixBrokenPreview(), "yes")

	if got.Status != APTFixBrokenApprovalStatusDeclined {
		t.Fatalf("status = %q, want declined for a bare \"yes\"", got.Status)
	}
}

func TestApproveAndApplyAPTFixBrokenRepairBlockedWhenPolicyDisabled(t *testing.T) {
	t.Setenv(APTFixBrokenRepairExecutionEnabledEnv, "false")

	got := ApproveAndApplyAPTFixBrokenRepair(&fakeExecutor{}, readyAPTFixBrokenPreview(), aptFixBrokenRepairConfirmation)

	if got.Status != APTFixBrokenApprovalStatusBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(got.Reason, "CROSS_SUITE_FIXBROKEN_REPAIR_ENABLED") {
		t.Fatalf("reason should name the operator-policy env var, got: %s", got.Reason)
	}
}

func TestApproveAndApplyAPTFixBrokenRepairAppliesWhenFullyApproved(t *testing.T) {
	t.Setenv(APTFixBrokenRepairExecutionEnabledEnv, "true")
	exec := &fakeExecutor{
		runOutputs:     []string{safeNetworkFactsProbeOutput()},
		runSudoOutputs: []string{"", ""},
		runSudoLabelOutputs: []string{
			"0 upgraded, 0 newly installed, 1 removed",
			"",
			"",
		},
	}

	got := ApproveAndApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview(), aptFixBrokenRepairConfirmation)

	if got.Status != APTFixBrokenApprovalStatusApplied {
		t.Fatalf("status = %q, want applied (reason: %s)", got.Status, got.Reason)
	}
}

// TestApproveAndApplyAPTFixBrokenRepairDoesNotBlockItselfOnTheBrokenStateItFixes is a
// regression test for a real bug found by running this repair against a genuinely broken dpkg
// state in a live ubuntu:24.04 container (dpkg -i of a .deb with an unmet dependency): the
// safety gate's dpkg-health check blocked the repair with "dpkg --audit reports broken ...
// packages" — but a broken dpkg state is exactly the precondition this repair exists to fix,
// so it could never run against the one state that actually needs it. Every other mocked test
// in this file happened to set the safety probe's dpkg --audit to empty/healthy, which is why
// none of them caught this. The dpkg --audit text below is the exact real output captured from
// that container.
func TestApproveAndApplyAPTFixBrokenRepairDoesNotBlockItselfOnTheBrokenStateItFixes(t *testing.T) {
	t.Setenv(APTFixBrokenRepairExecutionEnabledEnv, "true")

	const realDpkgAuditOutput = "The following packages have been unpacked but not yet configured.\n" +
		"They must be configured using dpkg --configure or the configure\n" +
		"menu option in dselect for them to work:\n" +
		" cross-suite-test-broken deliberately broken test package for repohealer integr"

	exec := &fakeExecutor{
		runOutputs: []string{safeNetworkFactsProbeOutput()},
		// First RunSudo call is the safety gate's own dpkg --audit probe, deliberately
		// reporting the SAME broken package the repair is about to fix — this must not
		// block. Second is the apply step's targeted snapshot creation.
		runSudoOutputs: []string{realDpkgAuditOutput, ""},
		runSudoLabelOutputs: []string{
			"The following packages will be REMOVED:\n  cross-suite-test-broken\n0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.",
			"", // dpkg --audit after repair: clean
			"", // apt-get update after repair: clean
		},
	}

	got := ApproveAndApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview(), aptFixBrokenRepairConfirmation)

	if got.Status != APTFixBrokenApprovalStatusApplied {
		t.Fatalf(
			"status = %q, want applied — the repair must not block itself on the broken state it exists to fix (reason: %s)",
			got.Status,
			got.Reason,
		)
	}
}

func TestHashiCorpAPTListRepairSafetyBlockedExcludingDpkgBrokenIgnoresDpkg(t *testing.T) {
	safety := HashiCorpAPTListRepairSafety{
		DpkgBroken:      true,
		DpkgAuditOutput: "some broken package",
	}

	if blocked, reason := safety.BlockedExcludingDpkgBroken(); blocked {
		t.Fatalf("expected dpkg-broken to be excluded from this check, got blocked: %s", reason)
	}

	// Disk space and clock skew must still block normally.
	safety = HashiCorpAPTListRepairSafety{DiskSpaceLow: true, DiskEvidence: "disk full"}
	if blocked, _ := safety.BlockedExcludingDpkgBroken(); !blocked {
		t.Fatal("expected low disk space to still block")
	}

	safety = HashiCorpAPTListRepairSafety{ClockSkewSuspected: true, ClockEvidence: "clock skewed"}
	if blocked, _ := safety.BlockedExcludingDpkgBroken(); !blocked {
		t.Fatal("expected clock skew to still block")
	}
}

func TestApproveAndApplyAPTFixBrokenRepairNeverUnholdsPackages(t *testing.T) {
	// apt --fix-broken install never receives an unhold flag anywhere in this package;
	// guard that invariant directly against the apply script.
	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
		runSudoLabelOutputs: []string{
			"0 upgraded, 0 newly installed, 0 removed",
			"",
			"",
		},
	}

	ApplyAPTFixBrokenRepair(exec, readyAPTFixBrokenPreview())

	for _, command := range exec.commands {
		if strings.Contains(command, "unhold") {
			t.Fatalf("fix-broken repair must never unhold a package, found in: %s", command)
		}
	}
}
