package repohealer

import (
	"fmt"
	"strings"
)

func FormatDeb822RepairDryRun(result Deb822RepairDryRunResult) string {
	var builder strings.Builder

	builder.WriteString("Deb822 APT Repository Repair Preview\n")
	builder.WriteString(strings.Repeat("=", 80))
	builder.WriteString("\n")

	if !result.Ready {
		builder.WriteString("Preview status: Blocked\n")
		if strings.TrimSpace(result.Reason) != "" {
			builder.WriteString(fmt.Sprintf("Reason: %s\n", result.Reason))
		}
		builder.WriteString("No privileged command was executed.\n")
		return builder.String()
	}

	builder.WriteString("Preview status: Ready — no system changes made\n")
	builder.WriteString(fmt.Sprintf("Action: %s\n", result.ActionID))
	builder.WriteString(fmt.Sprintf("Finding: %s\n", result.FindingCode))
	builder.WriteString(fmt.Sprintf("Profile: %s (%s)\n", result.ProfileDisplayName, result.ProfileID))
	builder.WriteString(fmt.Sprintf("Repository: %s\n", result.RepositoryURL))
	builder.WriteString(fmt.Sprintf("Source file to replace: %s\n", result.SourceFile))
	builder.WriteString(fmt.Sprintf("Keyring file in scope: %s\n", result.KeyringPath))

	builder.WriteString("Snapshot targets:\n")
	for _, target := range result.SnapshotTargets {
		builder.WriteString(fmt.Sprintf("- %s\n", target))
	}

	builder.WriteString("Pinned signing-key fingerprints:\n")
	for _, fingerprint := range result.ExpectedFingerprints {
		builder.WriteString(fmt.Sprintf("- %s\n", fingerprint))
	}

	builder.WriteString("Rendered Deb822 replacement:\n")
	builder.WriteString(result.RenderedSource)
	if !strings.HasSuffix(result.RenderedSource, "\n") {
		builder.WriteString("\n")
	}

	builder.WriteString(
		"\nSafety: preview mode did not invoke sudo, create a snapshot, modify files, download keys, or run apt-get update.\n",
	)

	return builder.String()
}
