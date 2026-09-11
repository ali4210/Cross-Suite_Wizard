package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func dockerRepairResult() Result {
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
				RepositoryURL: "https://download.docker.com/linux/debian",
			},
		},
	}
}

func TestApplyKnownAPTRepairsBuildsDockerRepairCommand(t *testing.T) {
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

	got := ApplyKnownAPTRepairs(exec, dockerRepairResult())

	if !got.Attempted {
		t.Fatal("expected Docker repair to be attempted")
	}
	if got.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q, want docker-ce", got.ProfileID)
	}
	if got.Applied {
		t.Fatal("fingerprint mismatch must prevent Docker repair application")
	}
	if !got.RolledBack {
		t.Fatal("fingerprint mismatch must invoke targeted Docker rollback")
	}

	if len(exec.commands) < 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, and rollback commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create snapshot:\n%s", exec.commands[1])
	}

	repairCommand := exec.commands[2]

	for _, expected := range []string{
		`PROFILE_ID="docker-ce"`,
		`KEY_URL="https://download.docker.com/linux/debian/gpg"`,
		`KEYRING_PATH="/etc/apt/keyrings/docker.gpg"`,
		`SOURCE_FILE="/etc/apt/sources.list.d/docker.list"`,
		`SOURCE_LINE="deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable"`,
		`9DC858229FC7DD38854AE2D88D81803C0EBFCD88`,
		`D3306A018370199E527AE7997EA0A9C3F273FCD8`,
	} {
		if !strings.Contains(repairCommand, expected) {
			t.Fatalf("Docker repair command missing expected content %q:\n%s", expected, repairCommand)
		}
	}

	if !strings.Contains(exec.commands[len(exec.commands)-1], "SUDO:") {
		t.Fatalf("last command must perform rollback:\n%s", exec.commands[len(exec.commands)-1])
	}
}

func TestApplyKnownAPTRepairsRejectsDockerForUnsupportedSuite(t *testing.T) {
	exec := &fakeExecutor{}

	result := dockerRepairResult()
	result.Target.Codename = "unsupported-release"

	got := ApplyKnownAPTRepairs(exec, result)

	if !got.Attempted {
		t.Fatal("expected a matched Docker repair attempt")
	}
	if got.Applied {
		t.Fatal("unsupported Docker suite must not be repaired")
	}
	if got.RolledBack {
		t.Fatal("no snapshot/rollback should run when source rendering is blocked")
	}
	if got.Error == nil {
		t.Fatal("unsupported Docker suite must return an error")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unsupported Docker suite must not execute commands, got %d", len(exec.commands))
	}
}

func TestApplyKnownAPTRepairsAppliesDockerRepairAfterVerification(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
		},
	}

	got := ApplyKnownAPTRepairs(exec, dockerRepairResult())

	if !got.Attempted {
		t.Fatal("expected Docker repair attempt")
	}
	if !got.Applied {
		t.Fatalf("expected Docker repair to apply, got error: %v", got.Error)
	}
	if got.RolledBack {
		t.Fatal("successful Docker repair must not roll back")
	}
	if got.Error != nil {
		t.Fatalf("successful Docker repair returned error: %v", got.Error)
	}
	if got.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q, want docker-ce", got.ProfileID)
	}

	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected lock probe, snapshot, repair, and verification commands; got %d",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command must check APT/dpkg lock state:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SUDO:") {
		t.Fatalf("second command must create snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], `PROFILE_ID="docker-ce"`) {
		t.Fatalf("repair command does not target Docker:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[3], "apt-get update") {
		t.Fatalf("final command must verify APT update:\n%s", exec.commands[3])
	}
}

func TestApplyKnownAPTRepairsDoesNothingWhenNoFindingsExist(t *testing.T) {
	exec := &fakeExecutor{}

	result := dockerRepairResult()
	result.Findings = nil

	got := ApplyKnownAPTRepairs(exec, result)

	if got.Attempted {
		t.Fatal("no findings must not start a repair attempt")
	}
	if got.Applied {
		t.Fatal("no findings must not apply a repair")
	}
	if got.RolledBack {
		t.Fatal("no findings must not roll back")
	}
	if got.Error == nil {
		t.Fatal("no findings must report that no eligible repair exists")
	}
	if len(exec.commands) != 0 {
		t.Fatalf(
			"no findings must not execute commands; got %d",
			len(exec.commands),
		)
	}
}
