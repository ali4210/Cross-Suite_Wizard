package repohealer

import (
	"strings"
	"testing"
)

func TestFormatDeb822RepairDryRunForReadyPreview(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	preview := PreviewDeb822Repair(inspection, request)

	got := FormatDeb822RepairDryRun(preview)

	for _, want := range []string{
		"Deb822 APT Repository Repair Preview",
		"Preview status: Ready — no system changes made",
		"Action: " + request.ActionID,
		"Finding: " + request.FindingCode,
		"Source file to replace: " + request.SourceFile,
		"Keyring file in scope: " + request.KeyringPath,
		request.RenderedSource,
		"preview mode did not invoke sudo",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted preview missing %q:\n%s", want, got)
		}
	}
}

func TestFormatDeb822RepairDryRunForBlockedPreview(t *testing.T) {
	got := FormatDeb822RepairDryRun(Deb822RepairDryRunResult{
		Reason: "Deb822 execution request blocked: inspection does not match",
	})

	for _, want := range []string{
		"Preview status: Blocked",
		"Reason: Deb822 execution request blocked: inspection does not match",
		"No privileged command was executed.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted blocked preview missing %q:\n%s", want, got)
		}
	}
}
