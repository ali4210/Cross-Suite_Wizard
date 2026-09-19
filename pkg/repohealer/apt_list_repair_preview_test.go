package repohealer

import (
	"reflect"
	"strings"
	"testing"
)

func safeBlockedHashiCorpAPTListDoctorReport() APTListDoctorReport {
	return APTListDoctorReport{
		Overall: APTListDoctorStatusBlocked,
		Target: TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		ActionID:            "apt-keyring-repair-hashicorp",
		ProfileID:           HashiCorpAPTListProfileID,
		RepositoryURL:       HashiCorpAPTListRepositoryURL,
		SourceFile:          "/etc/apt/sources.list.d/hashicorp.list",
		SourceLine:          1,
		KeyringPath:         HashiCorpAPTListKeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		Checks: []APTListDoctorCheck{
			{
				Name:    "remote_source_file",
				Status:  APTListDoctorStatusReady,
				Message: "Remote source file is present and safely owned.",
			},
			{
				Name:    "remote_keyring_file",
				Status:  APTListDoctorStatusReady,
				Message: "Remote keyring file is present and safely owned.",
			},
			{
				Name:    "remote_apt_get",
				Status:  APTListDoctorStatusReady,
				Message: "Remote target provides apt-get.",
			},
			{
				Name:    "remote_gpg",
				Status:  APTListDoctorStatusReady,
				Message: "Remote target provides gpg.",
			},
			{
				Name:    "expected_signing_key",
				Status:  APTListDoctorStatusBlocked,
				Message: "The expected HashiCorp signing fingerprint is absent from the pinned keyring.",
			},
		},
	}
}

func TestPreviewBlockedHashiCorpAPTListRepairBuildsOfflinePlan(t *testing.T) {
	report := safeBlockedHashiCorpAPTListDoctorReport()
	before := report

	got := PreviewBlockedHashiCorpAPTListRepair(report)

	if !got.Ready {
		t.Fatalf("preview unexpectedly blocked: %s", got.Reason)
	}
	if got.ActionID != report.ActionID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, report.ActionID)
	}
	if got.ProfileID != HashiCorpAPTListProfileID {
		t.Fatalf("profile ID = %q", got.ProfileID)
	}
	if got.RepositoryURL != HashiCorpAPTListRepositoryURL {
		t.Fatalf("repository URL = %q", got.RepositoryURL)
	}
	if got.SourceFile != report.SourceFile || got.SourceLine != report.SourceLine {
		t.Fatalf("source = %q:%d, want %q:%d", got.SourceFile, got.SourceLine, report.SourceFile, report.SourceLine)
	}
	if got.KeyringPath != HashiCorpAPTListKeyringPath {
		t.Fatalf("keyring path = %q", got.KeyringPath)
	}
	if got.ExpectedFingerprint != HashiCorpAPTListExpectedFingerprint {
		t.Fatalf("fingerprint = %q", got.ExpectedFingerprint)
	}
	if got.KeyURL != "https://apt.releases.hashicorp.com/gpg" {
		t.Fatalf("key URL = %q", got.KeyURL)
	}
	if got.SafetyNotice != APTListRepairPreviewSafetyNotice {
		t.Fatalf("safety notice = %q", got.SafetyNotice)
	}
	if len(got.PlannedWrites) == 0 {
		t.Fatal("planned writes must be descriptive and non-empty")
	}
	if len(got.VerificationSteps) == 0 {
		t.Fatal("verification steps must be descriptive and non-empty")
	}
	if !reflect.DeepEqual(report, before) {
		t.Fatalf("preview mutated Doctor report: got %#v, want %#v", report, before)
	}
}

func TestPreviewBlockedHashiCorpAPTListRepairRefusesUnsafeReports(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APTListDoctorReport)
		want   string
	}{
		{
			name: "Doctor is ready",
			mutate: func(report *APTListDoctorReport) {
				report.Overall = APTListDoctorStatusReady
			},
			want: "must be blocked",
		},
		{
			name: "Wrong action",
			mutate: func(report *APTListDoctorReport) {
				report.ActionID = "different-action"
			},
			want: "action",
		},
		{
			name: "Wrong profile",
			mutate: func(report *APTListDoctorReport) {
				report.ProfileID = "docker-ce"
			},
			want: "profile",
		},
		{
			name: "Wrong repository",
			mutate: func(report *APTListDoctorReport) {
				report.RepositoryURL = "https://apt.releases.hashicorp.com.attacker.invalid"
			},
			want: "repository",
		},
		{
			name: "Wrong source path",
			mutate: func(report *APTListDoctorReport) {
				report.SourceFile = "/tmp/hashicorp.list"
			},
			want: "source",
		},
		{
			name: "Wrong keyring path",
			mutate: func(report *APTListDoctorReport) {
				report.KeyringPath = "/tmp/hashicorp.gpg"
			},
			want: "keyring",
		},
		{
			name: "Wrong fingerprint",
			mutate: func(report *APTListDoctorReport) {
				report.ExpectedFingerprint = "0000000000000000000000000000000000000000"
			},
			want: "fingerprint",
		},
		{
			name: "Unsafe preview permission",
			mutate: func(report *APTListDoctorReport) {
				report.CanPreview = true
			},
			want: "must not permit",
		},
		{
			name: "Unsupported target",
			mutate: func(report *APTListDoctorReport) {
				report.Target.PackageManager = ManagerUnknown
			},
			want: "Linux target using APT",
		},
		{
			name: "Source safety is blocked",
			mutate: func(report *APTListDoctorReport) {
				report.Checks[0].Status = APTListDoctorStatusBlocked
			},
			want: "remote_source_file",
		},
		{
			name: "Expected key is ready",
			mutate: func(report *APTListDoctorReport) {
				report.Checks[4].Status = APTListDoctorStatusReady
			},
			want: "expected_signing_key",
		},
		{
			name: "Expected key check missing",
			mutate: func(report *APTListDoctorReport) {
				report.Checks = report.Checks[:4]
			},
			want: "expected_signing_key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := safeBlockedHashiCorpAPTListDoctorReport()
			test.mutate(&report)

			got := PreviewBlockedHashiCorpAPTListRepair(report)

			if got.Ready {
				t.Fatalf("preview unexpectedly ready: %#v", got)
			}
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(test.want)) {
				t.Fatalf("reason = %q, want it to contain %q", got.Reason, test.want)
			}
			if got.SafetyNotice != APTListRepairPreviewSafetyNotice {
				t.Fatalf("safety notice = %q", got.SafetyNotice)
			}
		})
	}
}

func TestPreviewBlockedHashiCorpAPTListRepairCopiesResultSlices(t *testing.T) {
	first := PreviewBlockedHashiCorpAPTListRepair(safeBlockedHashiCorpAPTListDoctorReport())
	second := PreviewBlockedHashiCorpAPTListRepair(safeBlockedHashiCorpAPTListDoctorReport())

	if !first.Ready || !second.Ready {
		t.Fatalf("expected ready previews: first=%#v second=%#v", first, second)
	}

	first.PlannedWrites[0] = "mutated"
	first.VerificationSteps[0] = "mutated"

	if second.PlannedWrites[0] == "mutated" || second.VerificationSteps[0] == "mutated" {
		t.Fatalf("preview results share mutable backing slices: %#v", second)
	}
}

func TestPreviewBlockedHashiCorpAPTListRepairRefusesDuplicateDoctorChecks(t *testing.T) {
	tests := []struct {
		name  string
		check APTListDoctorCheck
		want  string
	}{
		{
			name: "Duplicate source safety check",
			check: APTListDoctorCheck{
				Name:    "remote_source_file",
				Status:  APTListDoctorStatusBlocked,
				Message: "Conflicting duplicate check.",
			},
			want: "remote_source_file",
		},
		{
			name: "Duplicate expected signing key check",
			check: APTListDoctorCheck{
				Name:    "expected_signing_key",
				Status:  APTListDoctorStatusReady,
				Message: "Conflicting duplicate check.",
			},
			want: "expected_signing_key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := safeBlockedHashiCorpAPTListDoctorReport()
			report.Checks = append(report.Checks, test.check)

			got := PreviewBlockedHashiCorpAPTListRepair(report)

			if got.Ready {
				t.Fatalf("preview unexpectedly ready: %#v", got)
			}
			if !strings.Contains(got.Reason, test.want) {
				t.Fatalf("reason = %q, want it to contain %q", got.Reason, test.want)
			}
			if !strings.Contains(got.Reason, "ambiguous") {
				t.Fatalf("reason = %q, want ambiguous duplicate failure", got.Reason)
			}
		})
	}
}
