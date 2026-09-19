package repohealer

import (
	"strings"
	"testing"
)

func TestFormatAPTListRepairPreviewReady(t *testing.T) {
	preview := PreviewBlockedHashiCorpAPTListRepair(
		safeBlockedHashiCorpAPTListDoctorReport(),
	)
	if !preview.Ready {
		t.Fatalf("preview unexpectedly blocked: %s", preview.Reason)
	}

	got := FormatAPTListRepairPreview(preview)

	for _, want := range []string{
		"HashiCorp APT-list Repair Preview",
		"Preview status: Ready — no system changes made",
		"Action: apt-keyring-repair-hashicorp",
		"Profile: HashiCorp (hashicorp)",
		"Repository: https://apt.releases.hashicorp.com",
		"Source file: /etc/apt/sources.list.d/hashicorp.list (line 1)",
		"Keyring file: /usr/share/keyrings/hashicorp-archive-keyring.gpg",
		"Official key URL: https://apt.releases.hashicorp.com/gpg",
		"Required full fingerprint: D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
		"Planned writes:",
		"Verification after an approved future apply:",
		"Target file hashes and key material are not collected during this offline preview.",
		APTListRepairPreviewSafetyNotice,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted preview missing %q:\n%s", want, got)
		}
	}

	for _, write := range preview.PlannedWrites {
		if !strings.Contains(got, write) {
			t.Fatalf("formatted preview missing planned write %q:\n%s", write, got)
		}
	}

	for _, step := range preview.VerificationSteps {
		if !strings.Contains(got, step) {
			t.Fatalf("formatted preview missing verification step %q:\n%s", step, got)
		}
	}
}

func TestFormatAPTListRepairPreviewBlocked(t *testing.T) {
	preview := APTListRepairPreview{
		Reason:       "APT-list repair preview blocked: expected signing-key check is not blocked",
		SafetyNotice: APTListRepairPreviewSafetyNotice,
	}

	got := FormatAPTListRepairPreview(preview)

	for _, want := range []string{
		"HashiCorp APT-list Repair Preview",
		"Preview status: Blocked",
		"Reason: APT-list repair preview blocked: expected signing-key check is not blocked",
		APTListRepairPreviewSafetyNotice,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted blocked preview missing %q:\n%s", want, got)
		}
	}
}

func TestFormatAPTListRepairPreviewDoesNotMutatePreview(t *testing.T) {
	preview := PreviewBlockedHashiCorpAPTListRepair(
		safeBlockedHashiCorpAPTListDoctorReport(),
	)
	before := preview

	_ = FormatAPTListRepairPreview(preview)

	if len(preview.PlannedWrites) != len(before.PlannedWrites) ||
		len(preview.VerificationSteps) != len(before.VerificationSteps) {
		t.Fatalf("formatter changed preview slice lengths: got %#v want %#v", preview, before)
	}

	for index := range preview.PlannedWrites {
		if preview.PlannedWrites[index] != before.PlannedWrites[index] {
			t.Fatalf("formatter changed planned write %d: got %q want %q",
				index,
				preview.PlannedWrites[index],
				before.PlannedWrites[index],
			)
		}
	}

	for index := range preview.VerificationSteps {
		if preview.VerificationSteps[index] != before.VerificationSteps[index] {
			t.Fatalf("formatter changed verification step %d: got %q want %q",
				index,
				preview.VerificationSteps[index],
				before.VerificationSteps[index],
			)
		}
	}
}
