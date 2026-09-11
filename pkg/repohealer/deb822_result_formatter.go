package repohealer

import (
	"fmt"
	"strings"
)

func FormatDeb822RepairApprovalResult(
	result Deb822RepairApprovalResult,
) string {
	var builder strings.Builder

	builder.WriteString("Deb822 APT Repository Repair Result\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("Status: %s\n", displayDeb822ApprovalStatus(result.Status)))

	if strings.TrimSpace(result.ActionID) != "" {
		builder.WriteString(fmt.Sprintf("Action: %s\n", result.ActionID))
	}
	if strings.TrimSpace(result.ProfileID) != "" {
		builder.WriteString(fmt.Sprintf("Profile: %s\n", result.ProfileID))
	}
	if strings.TrimSpace(result.SourceFile) != "" {
		builder.WriteString(fmt.Sprintf("Source file: %s\n", result.SourceFile))
	}
	if strings.TrimSpace(result.KeyringPath) != "" {
		builder.WriteString(fmt.Sprintf("Keyring: %s\n", result.KeyringPath))
	}

	switch result.Status {
	case Deb822RepairApprovalStatusBlocked:
		builder.WriteString("\nRepair status: Blocked before execution\n")
		builder.WriteString("No privileged command was executed.\n")

	case Deb822RepairApprovalStatusDeclined:
		builder.WriteString("\nRepair status: Declined by operator\n")
		builder.WriteString("No privileged command was executed.\n")

	case Deb822RepairApprovalStatusApplied:
		builder.WriteString("\nRepair status: Applied successfully\n")
		builder.WriteString("Rollback: Not required\n")

	case Deb822RepairApprovalStatusFailed:
		builder.WriteString("\nRepair status: Failed\n")
		if result.ApplyResult.RolledBack {
			builder.WriteString("Rollback: Completed\n")
		} else if result.ApplyResult.Attempted {
			builder.WriteString("Rollback: Not completed\n")
		}
	}

	if result.ApplyResult.Attempted {
		builder.WriteString(
			fmt.Sprintf(
				"Repair attempted: %t\n",
				result.ApplyResult.Attempted,
			),
		)
	}

	if result.ApplyResult.Snapshot.ID != "" ||
		result.ApplyResult.Snapshot.Path != "" {
		builder.WriteString(
			fmt.Sprintf(
				"Snapshot: %s (%s)\n",
				result.ApplyResult.Snapshot.ID,
				result.ApplyResult.Snapshot.Path,
			),
		)
	}

	if strings.TrimSpace(result.Reason) != "" {
		builder.WriteString(fmt.Sprintf("\nReason: %s\n", result.Reason))
	}

	return builder.String()
}

func displayDeb822ApprovalStatus(
	status Deb822RepairApprovalStatus,
) string {
	switch status {
	case Deb822RepairApprovalStatusBlocked:
		return "Blocked"
	case Deb822RepairApprovalStatusDeclined:
		return "Declined"
	case Deb822RepairApprovalStatusApplied:
		return "Applied"
	case Deb822RepairApprovalStatusFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}
