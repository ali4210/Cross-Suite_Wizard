package repohealer

import (
	"fmt"
	"strings"
)

// FormatHashiCorpAPTListRepairApprovalResult renders an approval/apply outcome the same way
// FormatDeb822RepairApprovalResult does, including the exact BLOCKED/DECLINED/FAILED reason so
// an operator always sees why, and the next step when one applies.
func FormatHashiCorpAPTListRepairApprovalResult(
	result HashiCorpAPTListRepairApprovalResult,
) string {
	var builder strings.Builder

	builder.WriteString("HashiCorp APT-list Repair Result\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	builder.WriteString(fmt.Sprintf("Status: %s\n", result.Status))
	builder.WriteString(fmt.Sprintf("Action: %s\n", result.ActionID))
	builder.WriteString(fmt.Sprintf("Profile: %s\n", result.ProfileID))
	builder.WriteString(fmt.Sprintf("Keyring file: %s\n", result.KeyringPath))

	if strings.TrimSpace(result.Reason) != "" {
		builder.WriteString(fmt.Sprintf("Reason: %s\n", result.Reason))
	}

	apply := result.ApplyResult
	if apply.Attempted {
		builder.WriteString(fmt.Sprintf("Applied: %t\n", apply.Applied))
		builder.WriteString(fmt.Sprintf("Rolled back: %t\n", apply.RolledBack))
		if apply.Snapshot.Created {
			builder.WriteString(fmt.Sprintf(
				"Snapshot: %s (%s)\n",
				apply.Snapshot.ID,
				apply.Snapshot.Path,
			))
		}
		if strings.TrimSpace(apply.Output) != "" {
			builder.WriteString("Apply output:\n")
			builder.WriteString(apply.Output)
			builder.WriteString("\n")
		}
		if strings.TrimSpace(apply.VerificationOut) != "" {
			builder.WriteString("Verification output:\n")
			builder.WriteString(apply.VerificationOut)
			builder.WriteString("\n")
		}
	}

	switch result.Status {
	case HashiCorpAPTListRepairApprovalStatusApplied:
		builder.WriteString(
			"The HashiCorp APT-list signing key was restored and verified. " +
				"The pre-repair snapshot remains available for manual rollback via Option 9 if needed.\n",
		)
	case HashiCorpAPTListRepairApprovalStatusFailed:
		if apply.RolledBack {
			builder.WriteString(
				"The repair failed and was automatically rolled back to the pre-repair snapshot. No lasting system change was made.\n",
			)
		} else {
			builder.WriteString(
				"The repair failed and automatic rollback did not complete. Review the snapshot above and consider manual rollback via Option 9.\n",
			)
		}
	case HashiCorpAPTListRepairApprovalStatusDeclined:
		builder.WriteString("No system changes were made.\n")
	case HashiCorpAPTListRepairApprovalStatusBlocked:
		builder.WriteString("No system changes were made.\n")
	}

	return builder.String()
}
