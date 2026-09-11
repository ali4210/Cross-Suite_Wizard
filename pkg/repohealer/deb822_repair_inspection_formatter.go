package repohealer

import (
	"fmt"
	"strings"
)

func FormatDeb822RepairInspection(
	inspection Deb822RepairInspection,
) string {
	var builder strings.Builder

	builder.WriteString("Deb822 Repository Repair Inspection\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	if !inspection.Ready {
		builder.WriteString("Status: Blocked — no repair will run\n")
		writeDeb822InspectionIdentity(&builder, inspection)
		if strings.TrimSpace(inspection.BlockReason) != "" {
			builder.WriteString(
				fmt.Sprintf("Reason: %s\n", inspection.BlockReason),
			)
		}
		return builder.String()
	}

	builder.WriteString("Status: Ready for review — no repair will run\n")
	writeDeb822InspectionIdentity(&builder, inspection)

	builder.WriteString("\nFiles:\n")
	builder.WriteString(
		fmt.Sprintf("  Source: %s\n", inspection.SourceFile),
	)
	builder.WriteString(
		fmt.Sprintf("  Keyring: %s\n", inspection.KeyringPath),
	)

	builder.WriteString("\nRendered replacement:\n")
	for _, line := range strings.Split(
		strings.TrimSuffix(inspection.RenderedSource, "\n"),
		"\n",
	) {
		builder.WriteString(fmt.Sprintf("  %s\n", line))
	}

	builder.WriteString("\nFuture snapshot targets:\n")
	for _, target := range inspection.SnapshotTargets {
		if trimmed := strings.TrimSpace(target); trimmed != "" {
			builder.WriteString(fmt.Sprintf("  - %s\n", trimmed))
		}
	}

	builder.WriteString("\nInspection only: no repair was executed.\n")

	return builder.String()
}

func writeDeb822InspectionIdentity(
	builder *strings.Builder,
	inspection Deb822RepairInspection,
) {
	if strings.TrimSpace(inspection.ActionID) != "" {
		builder.WriteString(
			fmt.Sprintf("Action: %s\n", inspection.ActionID),
		)
	}
	if strings.TrimSpace(inspection.ProfileName) != "" ||
		strings.TrimSpace(inspection.ProfileID) != "" {
		builder.WriteString(fmt.Sprintf(
			"Profile: %s (%s)\n",
			inspection.ProfileName,
			inspection.ProfileID,
		))
	}
}
