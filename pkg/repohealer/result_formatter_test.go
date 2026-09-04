package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatApprovalExecutionResultForAppliedRepair(t *testing.T) {
	output := FormatApprovalExecutionResult(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:                 "apt-source-binding-repair-docker-ce",
			ProfileID:          "docker-ce",
			ProfileDisplayName: "Docker CE",
			FindingCode:        "APT_SOURCE_KEYRING_MISMATCH",
		},
		RepairResult: RepairResult{
			Attempted:       true,
			Applied:         true,
			ProfileID:       "docker-ce",
			Output:          "REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
			VerificationOut: "Hit:1 https://download.docker.com/linux/debian bookworm InRelease",
			Snapshot: Snapshot{
				ID:      "apt-test",
				Path:    "/var/lib/cross-suite/snapshots/apt-test",
				Created: true,
			},
		},
	})

	for _, expected := range []string{
		"APT Repository Repair Result",
		"Decision: Executed",
		"Action: apt-source-binding-repair-docker-ce",
		"Profile: Docker CE (docker-ce)",
		"Finding: APT_SOURCE_KEYRING_MISMATCH",
		"Repair status: Applied successfully",
		"Rollback: Not required",
		"Repair attempted: true",
		"Executed profile: docker-ce",
		"Snapshot: apt-test (/var/lib/cross-suite/snapshots/apt-test)",
		"REPAIR_APPLIED|docker-ce",
		"Verification output:",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("applied repair output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatApprovalExecutionResultForRolledBackFailure(t *testing.T) {
	output := FormatApprovalExecutionResult(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:                 "apt-keyring-repair-docker-ce",
			ProfileID:          "docker-ce",
			ProfileDisplayName: "Docker CE",
			FindingCode:        "APT_KEYRING_PATH_MISSING",
		},
		RepairResult: RepairResult{
			Attempted:  true,
			Applied:    false,
			RolledBack: true,
			ProfileID:  "docker-ce",
			Snapshot: Snapshot{
				ID:      "apt-test",
				Path:    "/var/lib/cross-suite/snapshots/apt-test",
				Created: true,
			},
		},
		Error: errors.New("keyring/source repair failed: exit status 22"),
	})

	for _, expected := range []string{
		"Decision: Executed",
		"Repair status: Failed",
		"Rollback: Completed",
		"Repair attempted: true",
		"Executed profile: docker-ce",
		"Reason: keyring/source repair failed: exit status 22",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("rolled-back repair output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatApprovalExecutionResultForBlockedRepair(t *testing.T) {
	output := FormatApprovalExecutionResult(ApprovalExecutionResult{
		Decision: ApprovalExecutionBlocked,
		Action: RepairAction{
			ID:                 "apt-source-binding-repair-docker-ce",
			ProfileID:          "docker-ce",
			ProfileDisplayName: "Docker CE",
			FindingCode:        "APT_SOURCE_KEYRING_MISMATCH",
			BlockReason:        "Docker Parrot suite review required: unsupported Parrot codename \"unsupported-release\"",
		},
		Error: errors.New("repair action is blocked"),
	})

	for _, expected := range []string{
		"Decision: Blocked",
		"Repair status: Blocked before execution",
		"No privileged command was executed.",
		"Docker Parrot suite review required",
		"Reason: repair action is blocked",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("blocked repair output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatApprovalExecutionResultForDeclinedRepair(t *testing.T) {
	output := FormatApprovalExecutionResult(ApprovalExecutionResult{
		Decision: ApprovalExecutionDeclined,
		Action: RepairAction{
			ID:                 "apt-keyring-repair-docker-ce",
			ProfileID:          "docker-ce",
			ProfileDisplayName: "Docker CE",
			FindingCode:        "APT_KEYRING_PATH_MISSING",
		},
		Error: errors.New("repair action was not explicitly approved"),
	})

	for _, expected := range []string{
		"Decision: Declined",
		"Repair status: Declined by operator",
		"No privileged command was executed.",
		"Reason: repair action was not explicitly approved",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("declined repair output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatApprovalExecutionResultForUnknownAction(t *testing.T) {
	output := FormatApprovalExecutionResult(ApprovalExecutionResult{
		Decision: ApprovalExecutionActionNotFound,
		Error:    errors.New("repair action \"apt-keyring-repair-not-real\" was not found in the current plan"),
	})

	for _, expected := range []string{
		"Decision: Action not found",
		"Repair status: Action not found",
		"No privileged command was executed.",
		"apt-keyring-repair-not-real",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("unknown action output missing %q:\n%s", expected, output)
		}
	}
}
