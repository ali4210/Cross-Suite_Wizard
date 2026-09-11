package repohealer

import (
	"fmt"
	"strings"
)

func FormatDeb822DoctorReport(report Deb822DoctorReport) string {
	var builder strings.Builder

	builder.WriteString("Repo Healer Deb822 Readiness Report\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("Overall: %s\n", report.Overall))
	builder.WriteString(fmt.Sprintf("Can preview: %t\n", report.CanPreview))
	builder.WriteString(fmt.Sprintf("Can apply: %t\n", report.CanApply))

	if report.ProfileID != "" {
		builder.WriteString(fmt.Sprintf("Profile: %s\n", report.ProfileID))
	}

	builder.WriteString(fmt.Sprintf("Audit path: %s\n", report.AuditPath))
	builder.WriteString("\nChecks:\n")

	for _, check := range report.Checks {
		builder.WriteString(
			fmt.Sprintf(
				"- [%s] %s: %s\n",
				check.Status,
				check.Name,
				check.Message,
			),
		)
	}

	builder.WriteString(
		"\nDoctor is read-only: it does not run repair commands, create target snapshots, modify files, or run apt-get update.\n",
	)

	return builder.String()
}
