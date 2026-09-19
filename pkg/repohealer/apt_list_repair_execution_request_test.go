package repohealer

import (
	"reflect"
	"strings"
	"testing"
)

func readyHashiCorpAPTListRepairPreview(t *testing.T) APTListRepairPreview {
	t.Helper()

	preview := PreviewBlockedHashiCorpAPTListRepair(
		safeBlockedHashiCorpAPTListDoctorReport(),
	)
	if !preview.Ready {
		t.Fatalf("preview unexpectedly blocked: %s", preview.Reason)
	}

	return preview
}

func TestBuildHashiCorpAPTListRepairExecutionRequestBindsExactPreview(t *testing.T) {
	preview := readyHashiCorpAPTListRepairPreview(t)
	before := preview

	got, err := BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		"REPAIR HASHICORP",
	)
	if err != nil {
		t.Fatalf("BuildHashiCorpAPTListRepairExecutionRequest() error = %v", err)
	}

	if got.ActionID != "apt-keyring-repair-hashicorp" {
		t.Fatalf("action ID = %q", got.ActionID)
	}
	if got.ProfileID != HashiCorpAPTListProfileID {
		t.Fatalf("profile ID = %q", got.ProfileID)
	}
	if got.RepositoryURL != HashiCorpAPTListRepositoryURL {
		t.Fatalf("repository URL = %q", got.RepositoryURL)
	}
	if got.SourceFile != "/etc/apt/sources.list.d/hashicorp.list" {
		t.Fatalf("source file = %q", got.SourceFile)
	}
	if got.SourceLine != 1 {
		t.Fatalf("source line = %d", got.SourceLine)
	}
	if got.KeyringPath != HashiCorpAPTListKeyringPath {
		t.Fatalf("keyring path = %q", got.KeyringPath)
	}
	if got.KeyURL != "https://apt.releases.hashicorp.com/gpg" {
		t.Fatalf("key URL = %q", got.KeyURL)
	}
	if got.ExpectedFingerprint != HashiCorpAPTListExpectedFingerprint {
		t.Fatalf("expected fingerprint = %q", got.ExpectedFingerprint)
	}
	if !reflect.DeepEqual(got.PlannedWrites, preview.PlannedWrites) {
		t.Fatalf("planned writes = %#v, want %#v", got.PlannedWrites, preview.PlannedWrites)
	}
	if !reflect.DeepEqual(got.VerificationSteps, preview.VerificationSteps) {
		t.Fatalf("verification steps = %#v, want %#v", got.VerificationSteps, preview.VerificationSteps)
	}
	if !reflect.DeepEqual(preview, before) {
		t.Fatalf("request builder mutated preview: got %#v want %#v", preview, before)
	}
}

func TestBuildHashiCorpAPTListRepairExecutionRequestCopiesSlices(t *testing.T) {
	preview := readyHashiCorpAPTListRepairPreview(t)

	first, err := BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		"REPAIR HASHICORP",
	)
	if err != nil {
		t.Fatalf("first request error = %v", err)
	}

	second, err := BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		"REPAIR HASHICORP",
	)
	if err != nil {
		t.Fatalf("second request error = %v", err)
	}

	first.PlannedWrites[0] = "mutated"
	first.VerificationSteps[0] = "mutated"

	if second.PlannedWrites[0] == "mutated" ||
		second.VerificationSteps[0] == "mutated" {
		t.Fatalf("requests share mutable slices: %#v", second)
	}
}

func TestBuildHashiCorpAPTListRepairExecutionRequestRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APTListRepairPreview)
		input  string
		want   string
	}{
		{
			name: "Preview is blocked",
			mutate: func(preview *APTListRepairPreview) {
				preview.Ready = false
				preview.Reason = "Doctor changed"
			},
			input: "REPAIR HASHICORP",
			want:  "preview is not ready",
		},
		{
			name:   "Wrong confirmation lowercase",
			mutate: func(preview *APTListRepairPreview) {},
			input:  "repair hashicorp",
			want:   "exact confirmation",
		},
		{
			name:   "Wrong confirmation whitespace",
			mutate: func(preview *APTListRepairPreview) {},
			input:  " REPAIR HASHICORP",
			want:   "exact confirmation",
		},
		{
			name: "Wrong action",
			mutate: func(preview *APTListRepairPreview) {
				preview.ActionID = "different-action"
			},
			input: "REPAIR HASHICORP",
			want:  "action",
		},
		{
			name: "Wrong profile",
			mutate: func(preview *APTListRepairPreview) {
				preview.ProfileID = "docker-ce"
			},
			input: "REPAIR HASHICORP",
			want:  "profile",
		},
		{
			name: "Wrong repository",
			mutate: func(preview *APTListRepairPreview) {
				preview.RepositoryURL = "https://example.invalid"
			},
			input: "REPAIR HASHICORP",
			want:  "repository",
		},
		{
			name: "Wrong source",
			mutate: func(preview *APTListRepairPreview) {
				preview.SourceFile = "/tmp/hashicorp.list"
			},
			input: "REPAIR HASHICORP",
			want:  "source file",
		},
		{
			name: "Invalid source line",
			mutate: func(preview *APTListRepairPreview) {
				preview.SourceLine = 0
			},
			input: "REPAIR HASHICORP",
			want:  "source line",
		},
		{
			name: "Wrong keyring",
			mutate: func(preview *APTListRepairPreview) {
				preview.KeyringPath = "/tmp/hashicorp.gpg"
			},
			input: "REPAIR HASHICORP",
			want:  "keyring",
		},
		{
			name: "Wrong key URL",
			mutate: func(preview *APTListRepairPreview) {
				preview.KeyURL = "https://example.invalid/gpg"
			},
			input: "REPAIR HASHICORP",
			want:  "key URL",
		},
		{
			name: "Wrong fingerprint",
			mutate: func(preview *APTListRepairPreview) {
				preview.ExpectedFingerprint = "0000000000000000000000000000000000000000"
			},
			input: "REPAIR HASHICORP",
			want:  "fingerprint",
		},
		{
			name: "Missing planned write",
			mutate: func(preview *APTListRepairPreview) {
				preview.PlannedWrites = nil
			},
			input: "REPAIR HASHICORP",
			want:  "planned writes",
		},
		{
			name: "Unexpected extra planned write",
			mutate: func(preview *APTListRepairPreview) {
				preview.PlannedWrites = append(preview.PlannedWrites, "extra")
			},
			input: "REPAIR HASHICORP",
			want:  "planned writes",
		},
		{
			name: "Missing verification step",
			mutate: func(preview *APTListRepairPreview) {
				preview.VerificationSteps = nil
			},
			input: "REPAIR HASHICORP",
			want:  "verification steps",
		},
		{
			name: "Unexpected verification step",
			mutate: func(preview *APTListRepairPreview) {
				preview.VerificationSteps = append(preview.VerificationSteps, "extra")
			},
			input: "REPAIR HASHICORP",
			want:  "verification steps",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preview := readyHashiCorpAPTListRepairPreview(t)
			preview.PlannedWrites = append([]string(nil), preview.PlannedWrites...)
			preview.VerificationSteps = append([]string(nil), preview.VerificationSteps...)
			test.mutate(&preview)

			got, err := BuildHashiCorpAPTListRepairExecutionRequest(
				preview,
				test.input,
			)
			if err == nil {
				t.Fatalf("unsafe request unexpectedly succeeded: %#v", got)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), test.want)
			}
			if !reflect.DeepEqual(
				got,
				HashiCorpAPTListRepairExecutionRequest{},
			) {
				t.Fatalf("blocked request must be empty, got %#v", got)
			}
		})
	}
}
