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
	if len(exec.commands) < 3 {
		t.Fatalf("expected snapshot, repair, and rollback commands; got %d", len(exec.commands))
	}
	if !strings.Contains(exec.commands[0], "SUDO:") {
		t.Fatalf("first command must create snapshot: %s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "Restoring Microsoft VS Code APT Trust") {
		t.Fatalf("second command must be repair attempt: %s", exec.commands[1])
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
	if len(exec.commands) < 4 {
		t.Fatalf("expected snapshot, repair, verification, rollback; got %d", len(exec.commands))
	}
	if !strings.Contains(exec.commands[2], "Verifying APT Repository Health") {
		t.Fatalf("third command must be verification: %s", exec.commands[2])
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

	if len(exec.commands) < 2 {
		t.Fatalf("expected snapshot and repair commands, got %d", len(exec.commands))
	}

	repairCommand := exec.commands[1]
	for _, fingerprint := range profile.ExpectedFingerprints {
		if !strings.Contains(repairCommand, fingerprint) {
			t.Fatalf(
				"repair command does not include pinned Docker fingerprint %s",
				fingerprint,
			)
		}
	}
}
