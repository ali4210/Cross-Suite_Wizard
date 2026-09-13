package repohealer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAPTListDoctorExitCode(t *testing.T) {
	tests := []struct {
		name   string
		status APTListDoctorStatus
		want   int
	}{
		{
			name:   "Ready",
			status: APTListDoctorStatusReady,
			want:   APTListDoctorExitReady,
		},
		{
			name:   "Warning",
			status: APTListDoctorStatusWarning,
			want:   APTListDoctorExitWarning,
		},
		{
			name:   "Blocked",
			status: APTListDoctorStatusBlocked,
			want:   APTListDoctorExitBlocked,
		},
		{
			name:   "Unsupported",
			status: APTListDoctorStatusUnsupported,
			want:   APTListDoctorExitUnsupported,
		},
		{
			name:   "Unknown",
			status: APTListDoctorStatus("unexpected"),
			want:   APTListDoctorExitUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := APTListDoctorExitCode(test.status); got != test.want {
				t.Fatalf(
					"APTListDoctorExitCode(%q) = %d, want %d",
					test.status,
					got,
					test.want,
				)
			}
		})
	}
}

func TestAPTListDoctorHashiCorpProfileConstants(t *testing.T) {
	if HashiCorpAPTListProfileID != "hashicorp" {
		t.Fatalf(
			"profile ID = %q, want %q",
			HashiCorpAPTListProfileID,
			"hashicorp",
		)
	}
	if HashiCorpAPTListRepositoryURL !=
		"https://apt.releases.hashicorp.com" {
		t.Fatalf(
			"repository URL = %q",
			HashiCorpAPTListRepositoryURL,
		)
	}
	if HashiCorpAPTListKeyringPath !=
		"/usr/share/keyrings/hashicorp-archive-keyring.gpg" {
		t.Fatalf(
			"keyring path = %q",
			HashiCorpAPTListKeyringPath,
		)
	}

	const wantFingerprint = "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"
	if HashiCorpAPTListExpectedFingerprint != wantFingerprint {
		t.Fatalf(
			"expected fingerprint = %q, want %q",
			HashiCorpAPTListExpectedFingerprint,
			wantFingerprint,
		)
	}
	if !strings.HasSuffix(
		HashiCorpAPTListExpectedFingerprint,
		"FC9CA96ACA026560",
	) {
		t.Fatalf(
			"expected fingerprint = %q, want new key suffix %q",
			HashiCorpAPTListExpectedFingerprint,
			"FC9CA96ACA026560",
		)
	}
}

func TestValidateAPTListDoctorReportSafetyInvariants(t *testing.T) {
	tests := []struct {
		name    string
		report  APTListDoctorReport
		wantErr string
	}{
		{
			name: "Ready with all permissions",
			report: APTListDoctorReport{
				Overall:    APTListDoctorStatusReady,
				CanInspect: true,
				CanPreview: true,
				CanApply:   true,
			},
		},
		{
			name: "Ready without all permissions",
			report: APTListDoctorReport{
				Overall:    APTListDoctorStatusReady,
				CanInspect: true,
				CanPreview: true,
			},
			wantErr: "ready APT list Doctor report must permit",
		},
		{
			name: "Warning cannot permit mutation",
			report: APTListDoctorReport{
				Overall:    APTListDoctorStatusWarning,
				CanInspect: true,
			},
			wantErr: "warning APT list Doctor report must not permit",
		},
		{
			name: "Blocked cannot permit mutation",
			report: APTListDoctorReport{
				Overall:  APTListDoctorStatusBlocked,
				CanApply: true,
			},
			wantErr: "blocked APT list Doctor report must not permit",
		},
		{
			name: "Unsupported cannot permit mutation",
			report: APTListDoctorReport{
				Overall:    APTListDoctorStatusUnsupported,
				CanPreview: true,
			},
			wantErr: "unsupported APT list Doctor report must not permit",
		},
		{
			name: "Unknown cannot permit mutation",
			report: APTListDoctorReport{
				Overall:    APTListDoctorStatusUnknown,
				CanInspect: true,
			},
			wantErr: "unknown APT list Doctor report must not permit",
		},
		{
			name: "Unexpected status",
			report: APTListDoctorReport{
				Overall: APTListDoctorStatus("invalid"),
			},
			wantErr: "unknown APT list Doctor status",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateAPTListDoctorReport(test.report)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf(
						"ValidateAPTListDoctorReport() error = %v",
						err,
					)
				}
				return
			}

			if err == nil {
				t.Fatal(
					"ValidateAPTListDoctorReport() unexpectedly succeeded",
				)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantErr,
				)
			}
		})
	}
}

func TestMarshalAPTListDoctorReportJSON(t *testing.T) {
	report := APTListDoctorReport{
		Overall: APTListDoctorStatusBlocked,
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
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
				Name:    "expected_signing_key",
				Status:  APTListDoctorStatusBlocked,
				Message: "Expected HashiCorp signing key is absent.",
			},
		},
	}

	encoded, err := MarshalAPTListDoctorReportJSON(report)
	if err != nil {
		t.Fatalf("MarshalAPTListDoctorReportJSON() error = %v", err)
	}

	var decoded APTListDoctorReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Overall != report.Overall ||
		decoded.Target != report.Target ||
		decoded.ActionID != report.ActionID ||
		decoded.ProfileID != report.ProfileID ||
		decoded.RepositoryURL != report.RepositoryURL ||
		decoded.SourceFile != report.SourceFile ||
		decoded.SourceLine != report.SourceLine ||
		decoded.KeyringPath != report.KeyringPath ||
		decoded.ExpectedFingerprint != report.ExpectedFingerprint ||
		decoded.CanInspect != report.CanInspect ||
		decoded.CanPreview != report.CanPreview ||
		decoded.CanApply != report.CanApply {
		t.Fatalf("decoded report = %#v, want %#v", decoded, report)
	}

	if len(decoded.Checks) != len(report.Checks) {
		t.Fatalf(
			"decoded check count = %d, want %d",
			len(decoded.Checks),
			len(report.Checks),
		)
	}
	if decoded.Checks[0] != report.Checks[0] {
		t.Fatalf(
			"decoded check = %#v, want %#v",
			decoded.Checks[0],
			report.Checks[0],
		)
	}
}

func TestMarshalAPTListDoctorReportJSONRejectsUnsafeReport(t *testing.T) {
	_, err := MarshalAPTListDoctorReportJSON(APTListDoctorReport{
		Overall:    APTListDoctorStatusBlocked,
		CanInspect: true,
	})
	if err == nil {
		t.Fatal(
			"MarshalAPTListDoctorReportJSON() unexpectedly accepted unsafe report",
		)
	}
	if !strings.Contains(
		err.Error(),
		"blocked APT list Doctor report must not permit",
	) {
		t.Fatalf("error = %q", err.Error())
	}
}
