package repohealer

import (
	"fmt"
	"strings"
)

func FormatRepairAction(action RepairAction) string {
	var builder strings.Builder

	builder.WriteString("APT Repository Repair Plan\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	if !action.Eligible {
		builder.WriteString("Status: Blocked — no repair will run\n")
		if strings.TrimSpace(action.ProfileDisplayName) != "" {
			builder.WriteString(fmt.Sprintf(
				"Profile: %s (%s)\n",
				action.ProfileDisplayName,
				action.ProfileID,
			))
		}
		if strings.TrimSpace(action.FindingCode) != "" {
			builder.WriteString(fmt.Sprintf("Finding: %s\n", action.FindingCode))
		}
		if strings.TrimSpace(action.RepositoryURL) != "" {
			builder.WriteString(fmt.Sprintf("Repository: %s\n", action.RepositoryURL))
		}
		if strings.TrimSpace(action.BlockReason) != "" {
			builder.WriteString(fmt.Sprintf("Reason: %s\n", action.BlockReason))
		}
		return builder.String()
	}

	builder.WriteString("Status: Eligible — explicit approval required\n")
	builder.WriteString(fmt.Sprintf(
		"Profile: %s (%s)\n",
		action.ProfileDisplayName,
		action.ProfileID,
	))
	builder.WriteString(fmt.Sprintf("Finding: %s\n", action.FindingCode))
	builder.WriteString(fmt.Sprintf("Repository: %s\n", action.RepositoryURL))

	builder.WriteString("\nTarget:\n")
	builder.WriteString(fmt.Sprintf("  Platform: %s\n", action.Target.Platform))
	builder.WriteString(fmt.Sprintf("  Distribution: %s\n", action.Target.Distribution))
	builder.WriteString(fmt.Sprintf("  Version: %s\n", action.Target.Version))
	builder.WriteString(fmt.Sprintf("  Codename: %s\n", action.Target.Codename))
	builder.WriteString(fmt.Sprintf("  Architecture: %s\n", action.Target.Architecture))
	builder.WriteString(fmt.Sprintf("  Package manager: %s\n", action.Target.PackageManager))

	builder.WriteString("\nTrust:\n")
	builder.WriteString(fmt.Sprintf("  Key URL: %s\n", action.KeyURL))
	builder.WriteString("  Allowed fingerprints:\n")
	for _, fingerprint := range action.ExpectedFingerprints {
		builder.WriteString(fmt.Sprintf("  - %s\n", fingerprint))
	}

	builder.WriteString("\nFiles:\n")
	builder.WriteString(fmt.Sprintf("  Keyring: %s\n", action.KeyringPath))
	builder.WriteString(fmt.Sprintf("  Source: %s\n", action.SourceFile))
	builder.WriteString("  Snapshot targets:\n")
	for _, target := range action.SnapshotTargets {
		builder.WriteString(fmt.Sprintf("  - %s\n", target))
	}

	builder.WriteString("\nRendered source:\n")
	builder.WriteString(fmt.Sprintf("  %s\n", action.RenderedSource))

	writeStringList(&builder, "\nPlanned steps:", action.Commands)
	writeStringList(&builder, "\nVerification:", action.Verification)
	writeStringList(&builder, "\nRollback:", action.Rollback)

	return builder.String()
}

func writeStringList(builder *strings.Builder, heading string, values []string) {
	if len(values) == 0 {
		return
	}

	builder.WriteString(heading)
	builder.WriteString("\n")
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			builder.WriteString(fmt.Sprintf("  - %s\n", trimmed))
		}
	}
}
