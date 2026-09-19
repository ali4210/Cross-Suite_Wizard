package repohealer

import (
	"strings"
	"testing"
)

func TestFormatHashiCorpAPTListRepairApprovalResultForAppliedRepair(
	t *testing.T,
) {
	output := FormatHashiCorpAPTListRepairApprovalResult(
		HashiCorpAPTListRepairApprovalResult{
			Status:      HashiCorpAPTListRepairApprovalApplied,
			ActionID:    "apt-list-repair-hashicorp",
			ProfileID:   HashiCorpAPTListProfileID,
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			Execution: HashiCorpAPTListRepairExecutionResult{
				Attempted: true,
				Applied:   true,
			},
		},
	)

	for _, want := range []string{
		"HashiCorp APT-list Repair Result",
		"Status: Applied",
		"Action: apt-list-repair-hashicorp",
		"Profile: hashicorp",
		"Keyring: /usr/share/keyrings/hashicorp-archive-keyring.gpg",
		"Repair status: Applied successfully",
		"Rollback: Not required",
		"Repair attempted: true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q: %q", want, output)
		}
	}
}

func TestFormatHashiCorpAPTListRepairApprovalResultForRolledBackFailure(
	t *testing.T,
) {
	output := FormatHashiCorpAPTListRepairApprovalResult(
		HashiCorpAPTListRepairApprovalResult{
			Status:      HashiCorpAPTListRepairApprovalFailed,
			ActionID:    "apt-list-repair-hashicorp",
			ProfileID:   HashiCorpAPTListProfileID,
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			Execution: HashiCorpAPTListRepairExecutionResult{
				Attempted:       true,
				RolledBack:      true,
				Output:          "RAW_MUTATION_OUTPUT_MUST_NOT_APPEAR",
				VerificationOut: "RAW_VERIFICATION_OUTPUT_MUST_NOT_APPEAR",
			},
			Reason: "HashiCorp APT-list repair verification failed",
		},
	)

	for _, want := range []string{
		"Status: Failed",
		"Repair status: Failed",
		"Rollback: Completed",
		"Repair attempted: true",
		"Reason: HashiCorp APT-list repair verification failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q: %q", want, output)
		}
	}

	for _, forbidden := range []string{
		"RAW_MUTATION_OUTPUT_MUST_NOT_APPEAR",
		"RAW_VERIFICATION_OUTPUT_MUST_NOT_APPEAR",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output must not contain %q: %q", forbidden, output)
		}
	}
}

func TestFormatHashiCorpAPTListRepairApprovalResultForBlockedRepair(
	t *testing.T,
) {
	output := FormatHashiCorpAPTListRepairApprovalResult(
		HashiCorpAPTListRepairApprovalResult{
			Status:      HashiCorpAPTListRepairApprovalBlocked,
			ActionID:    "apt-list-repair-hashicorp",
			ProfileID:   HashiCorpAPTListProfileID,
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			Reason:      "operator policy is disabled",
		},
	)

	for _, want := range []string{
		"Status: Blocked",
		"Repair status: Blocked before execution",
		"No privileged command was executed.",
		"Reason: operator policy is disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q: %q", want, output)
		}
	}
}
