package repohealer

import (
	"fmt"
	"strings"
)

func FormatHashiCorpAPTListRepairApprovalResult(
	result HashiCorpAPTListRepairApprovalResult,
) string {
	var builder strings.Builder

	builder.WriteString("HashiCorp APT-list Repair Result\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")
	builder.WriteString(
		fmt.Sprintf(
			"Status: %s\n",
			displayHashiCorpAPTListRepairApprovalStatus(result.Status),
		),
	)

	if strings.TrimSpace(result.ActionID) != "" {
		builder.WriteString(fmt.Sprintf("Action: %s\n", result.ActionID))
	}
	if strings.TrimSpace(result.ProfileID) != "" {
		builder.WriteString(fmt.Sprintf("Profile: %s\n", result.ProfileID))
	}
	if strings.TrimSpace(result.KeyringPath) != "" {
		builder.WriteString(fmt.Sprintf("Keyring: %s\n", result.KeyringPath))
	}

	switch result.Status {
	case HashiCorpAPTListRepairApprovalBlocked:
		builder.WriteString("\nRepair status: Blocked before execution\n")
		builder.WriteString("No privileged command was executed.\n")

	case HashiCorpAPTListRepairApprovalApplied:
		builder.WriteString("\nRepair status: Applied successfully\n")
		builder.WriteString("Rollback: Not required\n")

	case HashiCorpAPTListRepairApprovalFailed:
		builder.WriteString("\nRepair status: Failed\n")
		if result.Execution.RolledBack {
			builder.WriteString("Rollback: Completed\n")
		} else if result.Execution.Attempted {
			builder.WriteString("Rollback: Not completed\n")
		}
	}

	if result.Execution.Attempted {
		builder.WriteString(
			fmt.Sprintf(
				"Repair attempted: %t\n",
				result.Execution.Attempted,
			),
		)
	}

	if strings.TrimSpace(result.Reason) != "" {
		builder.WriteString(fmt.Sprintf("\nReason: %s\n", result.Reason))
	}

	return builder.String()
}

func displayHashiCorpAPTListRepairApprovalStatus(
	status HashiCorpAPTListRepairApprovalStatus,
) string {
	switch status {
	case HashiCorpAPTListRepairApprovalBlocked:
		return "Blocked"
	case HashiCorpAPTListRepairApprovalApplied:
		return "Applied"
	case HashiCorpAPTListRepairApprovalFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}
