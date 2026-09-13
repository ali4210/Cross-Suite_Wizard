package repohealer

import (
	"encoding/json"
	"testing"
)

func TestDeb822DoctorExitCode(t *testing.T) {
	tests := []struct {
		name   string
		status Deb822DoctorStatus
		want   int
	}{
		{
			name:   "Ready",
			status: Deb822DoctorStatusReady,
			want:   Deb822DoctorExitReady,
		},
		{
			name:   "Warning",
			status: Deb822DoctorStatusWarning,
			want:   Deb822DoctorExitWarning,
		},
		{
			name:   "Blocked",
			status: Deb822DoctorStatusBlocked,
			want:   Deb822DoctorExitBlocked,
		},
		{
			name:   "Unsupported",
			status: Deb822DoctorStatusUnsupported,
			want:   Deb822DoctorExitUnsupported,
		},
		{
			name:   "Unknown",
			status: Deb822DoctorStatus("unexpected"),
			want:   Deb822DoctorExitUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Deb822DoctorExitCode(test.status); got != test.want {
				t.Fatalf(
					"Deb822DoctorExitCode(%q) = %d, want %d",
					test.status,
					got,
					test.want,
				)
			}
		})
	}
}

func TestMarshalDeb822DoctorReportJSON(t *testing.T) {
	report := Deb822DoctorReport{
		Overall: Deb822DoctorStatusWarning,
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		ProfileID:  "docker-ce",
		AuditPath:  "/tmp/repohealer-audit.jsonl",
		CanPreview: true,
		CanApply:   false,
		Checks: []Deb822DoctorCheck{
			{
				Name:    "execution_policy",
				Status:  Deb822DoctorStatusWarning,
				Message: "Execution is disabled.",
			},
		},
	}

	encoded, err := MarshalDeb822DoctorReportJSON(report)
	if err != nil {
		t.Fatalf("MarshalDeb822DoctorReportJSON() error = %v", err)
	}

	var decoded Deb822DoctorReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Overall != report.Overall ||
		decoded.Target != report.Target ||
		decoded.ProfileID != report.ProfileID ||
		decoded.AuditPath != report.AuditPath ||
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
	for index := range report.Checks {
		if decoded.Checks[index] != report.Checks[index] {
			t.Fatalf(
				"decoded check %d = %#v, want %#v",
				index,
				decoded.Checks[index],
				report.Checks[index],
			)
		}
	}
}
