package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func readyHashiCorpAPTListRepairPreflight(t *testing.T) HashiCorpAPTListRepairPreflight {
	t.Helper()

	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	report := blockedHashiCorpAPTListRepairDoctorReport(t)

	preflight := EvaluateHashiCorpAPTListRepairPreflight(request, probe, report)
	if !preflight.Ready {
		t.Fatalf("preflight unexpectedly blocked: %s", preflight.Reason)
	}

	return preflight
}

func TestApplyHashiCorpAPTListRepairAppliesSuccessfully(t *testing.T) {
	preflight := readyHashiCorpAPTListRepairPreflight(t)

	exec := &fakeExecutor{
		runSudoOutputs: []string{""},
		runSudoLabelOutputs: []string{
			"APTLIST_REPAIR_APPLIED|hashicorp|fingerprint=" + HashiCorpAPTListExpectedFingerprint,
			"",
		},
	}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if !got.Attempted {
		t.Fatal("expected apply to be attempted")
	}
	if !got.Applied {
		t.Fatalf("expected apply to succeed: %v", got.Error)
	}
	if got.RolledBack {
		t.Fatal("a successful apply must not roll back")
	}
	if got.Error != nil {
		t.Fatalf("unexpected error: %v", got.Error)
	}
	if !got.Snapshot.Created || got.Snapshot.Path == "" {
		t.Fatal("expected a created targeted snapshot before applying")
	}

	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, verification; got %d commands: %v",
			len(exec.commands),
			exec.commands,
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check the APT/dpkg lock state: %s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[2], "Restoring HashiCorp APT-list Signing Key") {
		t.Fatalf("third command must use the HashiCorp APT-list repair label: %s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[2], "apt.releases.hashicorp.com/gpg") {
		t.Fatalf("repair command must fetch the key only from the official URL: %s", exec.commands[2])
	}
	if strings.Contains(exec.commands[2], "keyserver") {
		t.Fatalf("repair command must never reference a keyserver: %s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "Verifying HashiCorp APT-list Repository Health") {
		t.Fatalf("fourth command must be verification: %s", exec.commands[3])
	}
}

func TestApplyHashiCorpAPTListRepairRollsBackOnFingerprintMismatch(t *testing.T) {
	preflight := readyHashiCorpAPTListRepairPreflight(t)

	exec := &fakeExecutor{
		runSudoOutputs: []string{"", ""},
		runSudoLabelOutputs: []string{
			"APTLIST_REPAIR_ERROR|fingerprint_mismatch|profile=hashicorp",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if !got.Attempted {
		t.Fatal("expected apply to be attempted")
	}
	if got.Applied {
		t.Fatal("a fingerprint mismatch must never be applied")
	}
	if !got.RolledBack {
		t.Fatal("a fingerprint mismatch must trigger an automatic rollback")
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "fingerprint_mismatch") {
		t.Fatalf("expected a fingerprint_mismatch error, got: %v", got.Error)
	}
}

func TestApplyHashiCorpAPTListRepairRollsBackOnDownloadFailure(t *testing.T) {
	preflight := readyHashiCorpAPTListRepairPreflight(t)

	exec := &fakeExecutor{
		runSudoOutputs:      []string{"", ""},
		runSudoLabelOutputs: []string{""},
		runSudoLabelErrors: []error{
			errors.New("curl: (6) Could not resolve host: apt.releases.hashicorp.com"),
		},
	}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if got.Applied {
		t.Fatal("a download failure must never be applied")
	}
	if !got.RolledBack {
		t.Fatal("a download failure must trigger an automatic rollback")
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "Could not resolve host") {
		t.Fatalf("expected the curl failure to surface in the error, got: %v", got.Error)
	}
}

func TestApplyHashiCorpAPTListRepairRollsBackOnVerificationFailure(t *testing.T) {
	preflight := readyHashiCorpAPTListRepairPreflight(t)

	exec := &fakeExecutor{
		runSudoOutputs: []string{"", ""},
		runSudoLabelOutputs: []string{
			"APTLIST_REPAIR_APPLIED|hashicorp|fingerprint=" + HashiCorpAPTListExpectedFingerprint,
			"Err:1 https://apt.releases.hashicorp.com stable InRelease\n  NO_PUBKEY AAAAAAAAAAAAAAAA",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 100"),
		},
	}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if got.Applied {
		t.Fatal("a failed post-repair verification must never be applied")
	}
	if !got.RolledBack {
		t.Fatal("a failed post-repair verification must trigger an automatic rollback")
	}
	if !strings.Contains(got.VerificationOut, "NO_PUBKEY") {
		t.Fatalf("expected verification evidence, got: %s", got.VerificationOut)
	}
}

func TestApplyHashiCorpAPTListRepairBlockedWhenPreflightNotReady(t *testing.T) {
	preflight := HashiCorpAPTListRepairPreflight{
		Ready:  false,
		Reason: "HashiCorp APT-list repair preflight blocked: required tool \"gpg\" is unavailable",
	}

	exec := &fakeExecutor{}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if !got.Attempted {
		t.Fatal("blocked preflight must still be reported as attempted")
	}
	if got.Applied || got.RolledBack {
		t.Fatal("blocked preflight must never apply or roll back")
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "preflight is not ready") {
		t.Fatalf("expected a preflight-not-ready error, got: %v", got.Error)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("blocked preflight must not execute any command, got %d", len(exec.commands))
	}
}

func TestApplyHashiCorpAPTListRepairBlocksBeforeSnapshotWhenAPTDpkgLockIsActive(t *testing.T) {
	preflight := readyHashiCorpAPTListRepairPreflight(t)

	exec := &fakeExecutor{
		lockProbeOutput: "APT_LOCK_ACTIVE|owners=12345",
		lockProbeError:  errors.New("exit status 20"),
	}

	got := ApplyHashiCorpAPTListRepair(exec, preflight)

	if !got.Attempted {
		t.Fatal("expected apply to be attempted")
	}
	if got.Applied || got.RolledBack {
		t.Fatal("an active lock must prevent apply or rollback")
	}
	if got.Snapshot.Created || got.Snapshot.Path != "" {
		t.Fatalf("an active lock must block before snapshot creation, got snapshot: %+v", got.Snapshot)
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "lock is active") {
		t.Fatalf("expected a lock-active error, got: %v", got.Error)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected only the lock probe to run, got %d commands: %v", len(exec.commands), exec.commands)
	}
}
