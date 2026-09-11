package repohealer

import (
	"errors"
	"strings"
	"testing"
)

type fakeExecutor struct {
	runOutputs          []string
	runSudoOutputs      []string
	runSudoLabelOutputs []string

	runErrors          []error
	runSudoErrors      []error
	runSudoLabelErrors []error

	lockProbeOutput string
	lockProbeError  error

	commands []string
}

func (f *fakeExecutor) Run(command string) (string, error) {
	f.commands = append(f.commands, "RUN: "+command)

	output := ""
	if len(f.runOutputs) > 0 {
		output = f.runOutputs[0]
		f.runOutputs = f.runOutputs[1:]
	}

	var err error
	if len(f.runErrors) > 0 {
		err = f.runErrors[0]
		f.runErrors = f.runErrors[1:]
	}

	return output, err
}

func (f *fakeExecutor) RunSudo(script string) (string, error) {
	f.commands = append(f.commands, "SUDO: "+script)

	output := ""
	if len(f.runSudoOutputs) > 0 {
		output = f.runSudoOutputs[0]
		f.runSudoOutputs = f.runSudoOutputs[1:]
	}

	var err error
	if len(f.runSudoErrors) > 0 {
		err = f.runSudoErrors[0]
		f.runSudoErrors = f.runSudoErrors[1:]
	}

	return output, err
}

func (f *fakeExecutor) RunSudoWithLabel(script, label string) (string, error) {
	f.commands = append(f.commands, "SUDO_LABEL["+label+"]: "+script)

	if label == "Checking APT/Dpkg Lock State" {
		return f.lockProbeOutput, f.lockProbeError
	}

	output := ""
	if len(f.runSudoLabelOutputs) > 0 {
		output = f.runSudoLabelOutputs[0]
		f.runSudoLabelOutputs = f.runSudoLabelOutputs[1:]
	}

	var err error
	if len(f.runSudoLabelErrors) > 0 {
		err = f.runSudoLabelErrors[0]
		f.runSudoLabelErrors = f.runSudoLabelErrors[1:]
	}

	return output, err
}

func microsoftRepairResult() Result {
	return Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://packages.microsoft.com/repos/code",
			},
		},
	}
}

func TestApplyKnownAPTRepairsReturnsNoActionForUnknownFinding(t *testing.T) {
	exec := &fakeExecutor{}

	result := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://unknown.example.invalid/apt",
			},
		},
	}

	got := ApplyKnownAPTRepairs(exec, result)

	if got.Attempted {
		t.Fatal("unknown repository must not start a repair attempt")
	}
	if got.Applied || got.RolledBack {
		t.Fatal("unknown repository must not be applied or rolled back")
	}
	if got.Error == nil {
		t.Fatal("unknown repository must return an error")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unknown repository must not execute commands, got %d", len(exec.commands))
	}
}

func TestApplyKnownAPTRepairsRollsBackOnFingerprintMismatch(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_ERROR|fingerprint_mismatch|expected=BC528686B50D79E339D3721CEB3E94ADBE1229CF|actual=0000000000000000000000000000000000000000",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyKnownAPTRepairs(exec, microsoftRepairResult())

	if !got.Attempted {
		t.Fatal("expected Microsoft repair attempt")
	}
	if got.Applied {
		t.Fatal("fingerprint mismatch must not apply repair")
	}
	if !got.RolledBack {
		t.Fatal("fingerprint mismatch must trigger targeted rollback")
	}
	if got.Error == nil {
		t.Fatal("fingerprint mismatch must return an error")
	}
	if got.Snapshot.Path == "" {
		t.Fatal("expected snapshot metadata before repair attempt")
	}
	if len(exec.commands) < 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, and rollback commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state: %s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create snapshot: %s", exec.commands[1])
	}

	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)
	if !ok {
		t.Fatal("expected Microsoft VS Code vendor profile")
	}

	expectedLabel := "Restoring " + profile.DisplayName + " APT Trust"
	if !strings.Contains(exec.commands[2], expectedLabel) {
		t.Fatalf(
			"third command must use the profile repair label %q: %s",
			expectedLabel,
			exec.commands[2],
		)
	}
	if !strings.Contains(exec.commands[len(exec.commands)-1], "SUDO:") {
		t.Fatalf("last command must be rollback: %s", exec.commands[len(exec.commands)-1])
	}
}

func TestApplyKnownAPTRepairsRollsBackOnAPTVerificationFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_APPLIED|microsoft-vscode|fingerprint=BC528686B50D79E339D3721CEB3E94ADBE1229CF|arch=amd64",
			"Err: https://packages.microsoft.com/repos/code stable InRelease\nNO_PUBKEY EB3E94ADBE1229CF",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 100"),
		},
	}

	got := ApplyKnownAPTRepairs(exec, microsoftRepairResult())

	if !got.Attempted {
		t.Fatal("expected Microsoft repair attempt")
	}
	if got.Applied {
		t.Fatal("failed APT verification must not be marked applied")
	}
	if !got.RolledBack {
		t.Fatal("failed APT verification must trigger targeted rollback")
	}
	if got.Error == nil {
		t.Fatal("failed APT verification must return an error")
	}
	if !strings.Contains(got.VerificationOut, "NO_PUBKEY EB3E94ADBE1229CF") {
		t.Fatalf("expected verification evidence, got: %s", got.VerificationOut)
	}
	if len(exec.commands) < 5 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, verification, rollback; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state: %s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[3], "Verifying APT Repository Health") {
		t.Fatalf("fourth command must be verification: %s", exec.commands[3])
	}
	if !strings.Contains(exec.commands[len(exec.commands)-1], "SUDO:") {
		t.Fatalf("last command must be rollback: %s", exec.commands[len(exec.commands)-1])
	}
}

func TestDockerRepairUsesAllPinnedFingerprints(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

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

	got := applyKnownAPTProfileRepair(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		profile,
	)

	if !got.Attempted {
		t.Fatal("expected Docker repair attempt")
	}
	if got.Applied {
		t.Fatal("Docker fingerprint mismatch must not apply a repair")
	}
	if !got.RolledBack {
		t.Fatal("Docker fingerprint mismatch must restore the targeted snapshot")
	}
	if got.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q, want docker-ce", got.ProfileID)
	}

	if len(exec.commands) < 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, and rollback commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state: %s", exec.commands[0])
	}

	repairCommand := exec.commands[2]
	for _, fingerprint := range profile.ExpectedFingerprints {
		if !strings.Contains(repairCommand, fingerprint) {
			t.Fatalf(
				"repair command does not include pinned Docker fingerprint %s",
				fingerprint,
			)
		}
	}
}

func TestApplyKnownAPTProfileRepairWithVerificationUsesInjectedFailingVerifier(t *testing.T) {
	const verificationScript = `
echo "TEST_VERIFICATION_FAILURE"
exit 42
`

	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_APPLIED|microsoft-vscode|fingerprint=BC528686B50D79E339D3721CEB3E94ADBE1229CF|arch=amd64",
			"TEST_VERIFICATION_FAILURE",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 42"),
		},
	}

	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)
	if !ok {
		t.Fatal("expected Microsoft VS Code vendor profile")
	}

	got := applyKnownAPTProfileRepairWithVerification(
		exec,
		microsoftRepairResult().Target,
		profile,
		verificationScript,
	)

	if !got.Attempted {
		t.Fatal("expected repair attempt")
	}
	if got.Applied {
		t.Fatal("an injected verifier failure must prevent repair application")
	}
	if !got.RolledBack {
		t.Fatal("an injected verifier failure must trigger rollback")
	}
	if got.Error == nil {
		t.Fatal("an injected verifier failure must return an error")
	}
	if got.VerificationOut != "TEST_VERIFICATION_FAILURE" {
		t.Fatalf("verification output = %q, want injected verifier output", got.VerificationOut)
	}

	if len(exec.commands) != 5 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, verification, rollback; got %d commands",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state: %s", exec.commands[0])
	}

	verificationCommand := exec.commands[3]
	if !strings.Contains(verificationCommand, "Verifying APT Repository Health") {
		t.Fatalf("expected verification label, got:\n%s", verificationCommand)
	}
	if !strings.Contains(verificationCommand, "TEST_VERIFICATION_FAILURE") {
		t.Fatalf(
			"verification command did not contain injected script:\n%s",
			verificationCommand,
		)
	}
	if strings.Contains(verificationCommand, "apt-get update") {
		t.Fatalf(
			"injected verification command must not fall back to production apt-get update:\n%s",
			verificationCommand,
		)
	}

	rollbackCommand := exec.commands[4]
	if !strings.Contains(rollbackCommand, "SUDO:") {
		t.Fatalf("last command must perform rollback, got:\n%s", rollbackCommand)
	}
}

func TestApplyKnownAPTRepairsBlocksBeforeSnapshotWhenAPTDpkgLockIsActive(t *testing.T) {
	exec := &fakeExecutor{
		lockProbeOutput: "APT_LOCK_ACTIVE|owners=12345",
		lockProbeError:  errors.New("exit status 20"),
	}

	got := ApplyKnownAPTRepairs(exec, microsoftRepairResult())

	if !got.Attempted {
		t.Fatal("expected known Microsoft repair to be considered attempted")
	}
	if got.Applied {
		t.Fatal("active APT/dpkg lock must prevent repair application")
	}
	if got.RolledBack {
		t.Fatal("active APT/dpkg lock must not create a snapshot or trigger rollback")
	}
	if got.Snapshot.Created || got.Snapshot.Path != "" {
		t.Fatalf("active lock must block before snapshot creation, got snapshot: %+v", got.Snapshot)
	}
	if got.Error == nil {
		t.Fatal("active APT/dpkg lock must return a blocking error")
	}
	if !strings.Contains(got.Error.Error(), "APT/dpkg package-manager lock is active") {
		t.Fatalf("unexpected lock error: %v", got.Error)
	}

	if len(exec.commands) != 1 {
		t.Fatalf(
			"expected only lock probe command, got %d commands: %v",
			len(exec.commands),
			exec.commands,
		)
	}

	lockProbe := exec.commands[0]
	if !strings.Contains(lockProbe, "Checking APT/Dpkg Lock State") {
		t.Fatalf("expected APT/dpkg lock probe label, got:\n%s", lockProbe)
	}
	if !strings.Contains(lockProbe, "/var/lib/dpkg/lock-frontend") {
		t.Fatalf("lock probe must check dpkg frontend lock:\n%s", lockProbe)
	}
	if !strings.Contains(lockProbe, "/var/lib/apt/lists/lock") {
		t.Fatalf("lock probe must check APT lists lock:\n%s", lockProbe)
	}
	if strings.Contains(lockProbe, "rm -f") ||
		strings.Contains(lockProbe, "kill ") ||
		strings.Contains(lockProbe, "killall") {
		t.Fatalf("lock probe must never remove locks or kill processes:\n%s", lockProbe)
	}
}
