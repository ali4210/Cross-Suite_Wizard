package repohealer

import (
	"fmt"
	"strings"
)

func FormatAPTListRepairPreview(preview APTListRepairPreview) string {
	var builder strings.Builder

	builder.WriteString("HashiCorp APT-list Repair Preview\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	if !preview.Ready {
		builder.WriteString("Preview status: Blocked\n")
		if strings.TrimSpace(preview.Reason) != "" {
			builder.WriteString(fmt.Sprintf("Reason: %s\n", preview.Reason))
		}
		builder.WriteString(APTListRepairPreviewSafetyNotice)
		builder.WriteString("\n")
		return builder.String()
	}

	builder.WriteString("Preview status: Ready — no system changes made\n")
	builder.WriteString(fmt.Sprintf("Action: %s\n", preview.ActionID))
	builder.WriteString(fmt.Sprintf(
		"Profile: %s (%s)\n",
		preview.ProfileDisplayName,
		preview.ProfileID,
	))
	builder.WriteString(fmt.Sprintf("Repository: %s\n", preview.RepositoryURL))
	builder.WriteString(fmt.Sprintf(
		"Source file: %s (line %d)\n",
		preview.SourceFile,
		preview.SourceLine,
	))
	builder.WriteString(fmt.Sprintf("Keyring file: %s\n", preview.KeyringPath))
	builder.WriteString(fmt.Sprintf("Official key URL: %s\n", preview.KeyURL))
	builder.WriteString(fmt.Sprintf(
		"Required full fingerprint: %s\n",
		preview.ExpectedFingerprint,
	))

	builder.WriteString("Planned writes:\n")
	for _, write := range preview.PlannedWrites {
		builder.WriteString(fmt.Sprintf("- %s\n", write))
	}

	builder.WriteString("Verification after an approved future apply:\n")
	for _, step := range preview.VerificationSteps {
		builder.WriteString(fmt.Sprintf("- %s\n", step))
	}

	builder.WriteString(
		"Target file hashes and key material are not collected during this offline preview.\n",
	)
	builder.WriteString(APTListRepairPreviewSafetyNotice)
	builder.WriteString("\n")

	return builder.String()
}
