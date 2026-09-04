package repohealer

import (
	"fmt"
	"strings"
)

func FormatApprovalExecutionResult(result ApprovalExecutionResult) string {
	var builder strings.Builder

	builder.WriteString("APT Repository Repair Result\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("Decision: %s\n", displayApprovalDecision(result.Decision)))

	if result.Action.ID != "" {
		builder.WriteString(fmt.Sprintf("Action: %s\n", result.Action.ID))
	}
	if result.Action.ProfileDisplayName != "" || result.Action.ProfileID != "" {
		builder.WriteString(fmt.Sprintf(
			"Profile: %s (%s)\n",
			result.Action.ProfileDisplayName,
			result.Action.ProfileID,
		))
	}
	if result.Action.FindingCode != "" {
		builder.WriteString(fmt.Sprintf("Finding: %s\n", result.Action.FindingCode))
	}

	switch result.Decision {
	case ApprovalExecutionDeclined:
		builder.WriteString("\nRepair status: Declined by operator\n")
		builder.WriteString("No privileged command was executed.\n")

	case ApprovalExecutionBlocked:
		builder.WriteString("\nRepair status: Blocked before execution\n")
		builder.WriteString("No privileged command was executed.\n")
		if strings.TrimSpace(result.Action.BlockReason) != "" {
			builder.WriteString(fmt.Sprintf("Reason: %s\n", result.Action.BlockReason))
		}

	case ApprovalExecutionActionNotFound:
		builder.WriteString("\nRepair status: Action not found\n")
		builder.WriteString("No privileged command was executed.\n")

	case ApprovalExecutionExecuted:
		formatExecutedRepairResult(&builder, result.RepairResult)
	}

	if result.Error != nil {
		builder.WriteString(fmt.Sprintf("\nReason: %v\n", result.Error))
	}

	return builder.String()
}

func formatExecutedRepairResult(builder *strings.Builder, repair RepairResult) {
	if repair.Applied {
		builder.WriteString("\nRepair status: Applied successfully\n")
		builder.WriteString("Rollback: Not required\n")
	} else {
		builder.WriteString("\nRepair status: Failed\n")
		if repair.RolledBack {
			builder.WriteString("Rollback: Completed\n")
		} else {
			builder.WriteString("Rollback: Not completed\n")
		}
	}

	builder.WriteString(fmt.Sprintf("Repair attempted: %t\n", repair.Attempted))

	if repair.ProfileID != "" {
		builder.WriteString(fmt.Sprintf("Executed profile: %s\n", repair.ProfileID))
	}
	if repair.Snapshot.ID != "" || repair.Snapshot.Path != "" {
		builder.WriteString(fmt.Sprintf(
			"Snapshot: %s (%s)\n",
			repair.Snapshot.ID,
			repair.Snapshot.Path,
		))
	}
	if strings.TrimSpace(repair.Output) != "" {
		builder.WriteString(fmt.Sprintf("Repair output: %s\n", repair.Output))
	}
	if strings.TrimSpace(repair.VerificationOut) != "" {
		builder.WriteString(fmt.Sprintf(
			"Verification output: %s\n",
			repair.VerificationOut,
		))
	}
}

func displayApprovalDecision(decision ApprovalExecutionDecision) string {
	switch decision {
	case ApprovalExecutionExecuted:
		return "Executed"
	case ApprovalExecutionDeclined:
		return "Declined"
	case ApprovalExecutionBlocked:
		return "Blocked"
	case ApprovalExecutionActionNotFound:
		return "Action not found"
	default:
		return "Unknown"
	}
}
