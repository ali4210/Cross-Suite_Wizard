package repohealer

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDeb822RepairExecutionOptions(t *testing.T) {
	got := defaultDeb822RepairExecutionOptions()

	if got.snapshotRoot != defaultAPTSnapshotRoot {
		t.Fatalf(
			"snapshot root = %q, want %q",
			got.snapshotRoot,
			defaultAPTSnapshotRoot,
		)
	}
	if got.temporaryRoot != "/var/tmp" {
		t.Fatalf("temporary root = %q, want /var/tmp", got.temporaryRoot)
	}
	if got.verificationScript != defaultAPTVerificationScript {
		t.Fatal("verification script does not use the production default")
	}
	if got.now == nil {
		t.Fatal("clock must be configured")
	}
}

func TestNormalizeDeb822RepairExecutionOptionsFillsOnlyMissingValues(t *testing.T) {
	fixedNow := func() time.Time {
		return time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC)
	}

	got := normalizeDeb822RepairExecutionOptions(
		deb822RepairExecutionOptions{
			snapshotRoot:       "/tmp/cross-suite-test-snapshots",
			temporaryRoot:      "/tmp/cross-suite-test-work",
			verificationScript: "exit 99",
			now:                fixedNow,
		},
	)

	if got.snapshotRoot != "/tmp/cross-suite-test-snapshots" {
		t.Fatalf("snapshot root = %q", got.snapshotRoot)
	}
	if got.temporaryRoot != "/tmp/cross-suite-test-work" {
		t.Fatalf("temporary root = %q", got.temporaryRoot)
	}
	if got.verificationScript != "exit 99" {
		t.Fatalf("verification script = %q", got.verificationScript)
	}
	if got.now().UTC() != fixedNow().UTC() {
		t.Fatalf("clock value = %s, want %s", got.now().UTC(), fixedNow().UTC())
	}
}

func TestNormalizeDeb822RepairExecutionOptionsUsesDefaults(t *testing.T) {
	got := normalizeDeb822RepairExecutionOptions(
		deb822RepairExecutionOptions{},
	)
	want := defaultDeb822RepairExecutionOptions()

	if got.snapshotRoot != want.snapshotRoot {
		t.Fatalf("snapshot root = %q, want %q", got.snapshotRoot, want.snapshotRoot)
	}
	if got.temporaryRoot != want.temporaryRoot {
		t.Fatalf("temporary root = %q, want %q", got.temporaryRoot, want.temporaryRoot)
	}
	if got.verificationScript != want.verificationScript {
		t.Fatal("verification script did not default")
	}
	if got.now == nil {
		t.Fatal("clock did not default")
	}
}

func TestApplyDeb822RepairExecutionWithOptionsUsesConfiguredPathsAndVerification(
	t *testing.T,
) {
	request := validDockerDeb822ExecutionRequest(t)
	targetRoot := t.TempDir()
	fixedTime := time.Date(2026, time.September, 12, 1, 2, 3, 456, time.UTC)

	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				request.ExpectedFingerprints[0] + "\n",
			"forced verification failure\n",
		},
		runSudoLabelErrors: []error{
			nil,
			fmt.Errorf("exit status 99"),
		},
	}

	got := applyDeb822RepairExecutionWithOptions(
		exec,
		request,
		deb822RepairExecutionOptions{
			targetRoot:         targetRoot,
			snapshotRoot:       "/tmp/cross-suite-test-snapshots",
			temporaryRoot:      "/tmp/cross-suite-test-work",
			verificationScript: "printf 'forced verification failure\\n'; exit 99",
			now: func() time.Time {
				return fixedTime
			},
		},
	)

	if got.Applied {
		t.Fatalf("forced verification failure unexpectedly applied: %#v", got)
	}
	if !got.RolledBack {
		t.Fatalf("forced verification failure did not roll back: %#v", got)
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "verification failed") {
		t.Fatalf("error = %v, want verification failure", got.Error)
	}
	if len(exec.commands) != 5 {
		t.Fatalf("command count = %d, want lock, snapshot, mutation, verification, rollback", len(exec.commands))
	}
	if !strings.Contains(exec.commands[1], `"/tmp/cross-suite-test-snapshots"`) {
		t.Fatalf("snapshot command did not use configured root:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], `"/tmp/cross-suite-test-work/cross-suite-deb822-repoheal-docker-ce-`) {
		t.Fatalf("mutation command did not use configured temporary root:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "forced verification failure") {
		t.Fatalf("verification command did not use configured script:\n%s", exec.commands[3])
	}

	resolvedSourceFile := filepath.Join(
		targetRoot,
		"etc",
		"apt",
		"sources.list.d",
		"docker.sources",
	)
	resolvedKeyringPath := filepath.Join(
		targetRoot,
		"etc",
		"apt",
		"keyrings",
		"docker.gpg",
	)

	if !strings.Contains(exec.commands[1], shellQuote(resolvedSourceFile)) {
		t.Fatalf(
			"snapshot command did not use resolved source path:\n%s",
			exec.commands[1],
		)
	}
	if !strings.Contains(exec.commands[1], shellQuote(resolvedKeyringPath)) {
		t.Fatalf(
			"snapshot command did not use resolved keyring path:\n%s",
			exec.commands[1],
		)
	}
	if !strings.Contains(
		exec.commands[2],
		"SOURCE_FILE="+shellQuote(resolvedSourceFile),
	) {
		t.Fatalf(
			"mutation command did not use resolved source path:\n%s",
			exec.commands[2],
		)
	}
	if !strings.Contains(
		exec.commands[2],
		"KEYRING_PATH="+shellQuote(resolvedKeyringPath),
	) {
		t.Fatalf(
			"mutation command did not use resolved keyring path:\n%s",
			exec.commands[2],
		)
	}
	if strings.Contains(
		exec.commands[2],
		"SOURCE_FILE="+shellQuote(request.SourceFile),
	) {
		t.Fatalf(
			"mutation command retained logical source path:\n%s",
			exec.commands[2],
		)
	}
	if strings.Contains(
		exec.commands[2],
		"KEYRING_PATH="+shellQuote(request.KeyringPath),
	) {
		t.Fatalf(
			"mutation command retained logical keyring path:\n%s",
			exec.commands[2],
		)
	}
	if got.SourceFile != request.SourceFile {
		t.Fatalf(
			"result source file = %q, want logical path %q",
			got.SourceFile,
			request.SourceFile,
		)
	}
	if got.KeyringPath != request.KeyringPath {
		t.Fatalf(
			"result keyring path = %q, want logical path %q",
			got.KeyringPath,
			request.KeyringPath,
		)
	}
}
