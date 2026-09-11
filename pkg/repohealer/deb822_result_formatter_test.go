package repohealer

import (
	"strings"
	"testing"
)

func TestFormatDeb822RepairApprovalResultForAppliedRepair(t *testing.T) {
	output := FormatDeb822RepairApprovalResult(Deb822RepairApprovalResult{
		Status:      Deb822RepairApprovalStatusApplied,
		ActionID:    "apt-source-binding-repair-docker-ce",
		ProfileID:   "docker-ce",
		SourceFile:  "/etc/apt/sources.list.d/docker.sources",
		KeyringPath: "/etc/apt/keyrings/docker.gpg",
		ApplyResult: Deb822RepairApplyResult{
			Attempted: true,
			Applied:   true,
			Snapshot: Snapshot{
				ID:      "apt-test",
				Path:    "/var/lib/cross-suite/snapshots/apt-test",
				Created: true,
			},
		},
	})

	for _, expected := range []string{
		"Deb822 APT Repository Repair Result",
		"Status: Applied",
		"Repair status: Applied successfully",
		"Rollback: Not required",
		"Action: apt-source-binding-repair-docker-ce",
		"Profile: docker-ce",
		"Source file: /etc/apt/sources.list.d/docker.sources",
		"Keyring: /etc/apt/keyrings/docker.gpg",
		"Repair attempted: true",
		"Snapshot: apt-test (/var/lib/cross-suite/snapshots/apt-test)",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatDeb822RepairApprovalResultForBlockedAndDeclined(t *testing.T) {
	tests := []struct {
		name     string
		result   Deb822RepairApprovalResult
		expected []string
	}{
		{
			name: "Blocked",
			result: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusBlocked,
				Reason: "inspection is not ready",
			},
			expected: []string{
				"Status: Blocked",
				"Repair status: Blocked before execution",
				"No privileged command was executed.",
				"Reason: inspection is not ready",
			},
		},
		{
			name: "Declined",
			result: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusDeclined,
				Reason: "Deb822 repair was not approved",
			},
			expected: []string{
				"Status: Declined",
				"Repair status: Declined by operator",
				"No privileged command was executed.",
				"Reason: Deb822 repair was not approved",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := FormatDeb822RepairApprovalResult(test.result)

			for _, expected := range test.expected {
				if !strings.Contains(output, expected) {
					t.Fatalf("output missing %q:\n%s", expected, output)
				}
			}
		})
	}
}

func TestFormatDeb822RepairApprovalResultForRolledBackFailure(t *testing.T) {
	output := FormatDeb822RepairApprovalResult(Deb822RepairApprovalResult{
		Status: Deb822RepairApprovalStatusFailed,
		Reason: "post-repair Deb822 APT verification failed",
		ApplyResult: Deb822RepairApplyResult{
			Attempted:  true,
			RolledBack: true,
		},
	})

	for _, expected := range []string{
		"Status: Failed",
		"Repair status: Failed",
		"Rollback: Completed",
		"Repair attempted: true",
		"Reason: post-repair Deb822 APT verification failed",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatDeb822RepairApprovalResultDoesNotExposeRawExecutionOutput(t *testing.T) {
	output := FormatDeb822RepairApprovalResult(Deb822RepairApprovalResult{
		Status: Deb822RepairApprovalStatusFailed,
		Reason: "safe failure summary",
		ApplyResult: Deb822RepairApplyResult{
			Attempted:       true,
			Output:          "SECRET_DEB822_MUTATION_OUTPUT",
			VerificationOut: "SECRET_DEB822_VERIFICATION_OUTPUT",
		},
	})

	for _, forbidden := range []string{
		"SECRET_DEB822_MUTATION_OUTPUT",
		"SECRET_DEB822_VERIFICATION_OUTPUT",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output must not contain %q:\n%s", forbidden, output)
		}
	}
}
