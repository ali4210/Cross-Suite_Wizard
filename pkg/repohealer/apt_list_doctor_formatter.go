package repohealer

import (
	"fmt"
	"strings"
)

func FormatAPTListDoctorReport(report APTListDoctorReport) string {
	var builder strings.Builder

	builder.WriteString("Repo Healer APT List Readiness Report\n")
	builder.WriteString("====================================\n")
	builder.WriteString(fmt.Sprintf("Overall: %s\n", report.Overall))
	builder.WriteString(fmt.Sprintf("Platform: %s\n", report.Target.Platform))
	builder.WriteString(fmt.Sprintf("Distribution: %s\n", report.Target.Distribution))
	builder.WriteString(fmt.Sprintf("Version: %s\n", report.Target.Version))
	builder.WriteString(fmt.Sprintf("Codename: %s\n", report.Target.Codename))
	builder.WriteString(fmt.Sprintf("Architecture: %s\n", report.Target.Architecture))
	builder.WriteString(fmt.Sprintf("Package manager: %s\n", report.Target.PackageManager))
	builder.WriteString(fmt.Sprintf("Action ID: %s\n", report.ActionID))
	builder.WriteString(fmt.Sprintf("Profile ID: %s\n", report.ProfileID))
	builder.WriteString(fmt.Sprintf("Repository URL: %s\n", report.RepositoryURL))
	builder.WriteString(fmt.Sprintf("Source file: %s\n", report.SourceFile))
	builder.WriteString(fmt.Sprintf("Source line: %d\n", report.SourceLine))
	builder.WriteString(fmt.Sprintf("Keyring path: %s\n", report.KeyringPath))
	builder.WriteString(
		fmt.Sprintf(
			"Expected fingerprint: %s\n",
			report.ExpectedFingerprint,
		),
	)
	builder.WriteString(
		fmt.Sprintf(
			"Permissions: inspect=%t preview=%t apply=%t\n",
			report.CanInspect,
			report.CanPreview,
			report.CanApply,
		),
	)

	builder.WriteString("\nChecks:\n")
	if len(report.Checks) == 0 {
		builder.WriteString("- none\n")
	} else {
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
	}

	return builder.String()
}
