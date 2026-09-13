package repohealer

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRunDeb822DoctorServiceReturnsReportJSONAndExitCode(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	facts := TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}

	got, err := RunDeb822DoctorService(facts, "docker-ce")
	if err != nil {
		t.Fatalf("RunDeb822DoctorService() error = %v", err)
	}

	if got.Report.Overall != Deb822DoctorStatusWarning {
		t.Fatalf(
			"overall status = %q, want %q",
			got.Report.Overall,
			Deb822DoctorStatusWarning,
		)
	}
	if got.ExitCode != Deb822DoctorExitWarning {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			Deb822DoctorExitWarning,
		)
	}
	if len(got.JSON) == 0 {
		t.Fatal("service JSON must not be empty")
	}

	var decoded Deb822DoctorReport
	if err := json.Unmarshal(got.JSON, &decoded); err != nil {
		t.Fatalf("service JSON is invalid: %v", err)
	}

	if decoded.Overall != got.Report.Overall ||
		decoded.Target != got.Report.Target ||
		decoded.ProfileID != got.Report.ProfileID ||
		decoded.AuditPath != got.Report.AuditPath ||
		decoded.CanPreview != got.Report.CanPreview ||
		decoded.CanApply != got.Report.CanApply {
		t.Fatalf("decoded report = %#v, want %#v", decoded, got.Report)
	}
}

func TestRunDeb822DoctorServiceReturnsUnsupportedExitCode(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	facts := TargetFacts{
		Platform:       PlatformWindows,
		Distribution:   "windows",
		Version:        "11",
		Architecture:   "amd64",
		PackageManager: ManagerWinget,
	}

	got, err := RunDeb822DoctorService(facts, "docker-ce")
	if err != nil {
		t.Fatalf("RunDeb822DoctorService() error = %v", err)
	}

	if got.Report.Overall != Deb822DoctorStatusUnsupported {
		t.Fatalf(
			"overall status = %q, want %q",
			got.Report.Overall,
			Deb822DoctorStatusUnsupported,
		)
	}
	if got.ExitCode != Deb822DoctorExitUnsupported {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			Deb822DoctorExitUnsupported,
		)
	}
}
