package repohealer

import (
	"fmt"
	"strings"
)

func FormatAPTFixBrokenPreview(preview APTFixBrokenPreview) string {
	var builder strings.Builder

	builder.WriteString("APT Fix-Broken-Install Preview\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	if preview.NothingToRepair {
		builder.WriteString("dpkg --audit reports no broken or inconsistent packages. There is nothing to repair.\n")
		return builder.String()
	}

	if !preview.Ready {
		builder.WriteString("Preview status: Blocked\n")
		if strings.TrimSpace(preview.Reason) != "" {
			builder.WriteString(fmt.Sprintf("Reason: %s\n", preview.Reason))
		}
		return builder.String()
	}

	builder.WriteString("Preview status: Ready — no system changes made\n\n")
	builder.WriteString("Actual dpkg --audit output:\n")
	builder.WriteString(preview.DpkgAuditOutput)
	builder.WriteString("\n\n")
	builder.WriteString("Simulated plan (apt-get -s --fix-broken install; dry run, no system changes):\n")
	builder.WriteString(preview.SimulatedPlan)
	builder.WriteString("\n\nPREVIEW ONLY: no system changes were made.\n")

	return builder.String()
}

func FormatAPTFixBrokenApprovalResult(result APTFixBrokenApprovalResult) string {
	var builder strings.Builder

	builder.WriteString("APT Fix-Broken-Install Result\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("Status: %s\n", result.Status))

	if strings.TrimSpace(result.Reason) != "" {
		builder.WriteString(fmt.Sprintf("Reason: %s\n", result.Reason))
	}

	apply := result.ApplyResult
	if apply.Attempted {
		builder.WriteString(fmt.Sprintf("Applied: %t\n", apply.Applied))
		builder.WriteString(fmt.Sprintf("Rolled back: %t\n", apply.RolledBack))
		if apply.Snapshot.Created {
			builder.WriteString(fmt.Sprintf("Snapshot: %s (%s)\n", apply.Snapshot.ID, apply.Snapshot.Path))
		}
		if strings.TrimSpace(apply.Output) != "" {
			builder.WriteString("apt --fix-broken install output:\n")
			builder.WriteString(apply.Output)
			builder.WriteString("\n")
		}
		if strings.TrimSpace(apply.DpkgAuditAfter) != "" {
			builder.WriteString("dpkg --audit after repair:\n")
			builder.WriteString(apply.DpkgAuditAfter)
			builder.WriteString("\n")
		}
	}

	switch result.Status {
	case APTFixBrokenApprovalStatusApplied:
		builder.WriteString("Broken/inconsistent packages were repaired and verified. No package was unheld automatically.\n")
	case APTFixBrokenApprovalStatusFailed:
		if apply.RolledBack {
			builder.WriteString("The repair failed and was automatically rolled back to the pre-repair dpkg database. No lasting system change was made.\n")
		} else {
			builder.WriteString("The repair failed and automatic rollback did not complete. Review the snapshot above and consider manual rollback via Option 9.\n")
		}
	default:
		builder.WriteString("No system changes were made.\n")
	}

	return builder.String()
}
