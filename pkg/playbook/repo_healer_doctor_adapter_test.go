package playbook

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

func doctorAdapterFacts() repohealer.TargetFacts {
	return repohealer.TargetFacts{
		Platform:       repohealer.PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: repohealer.ManagerAPT,
	}
}

func TestRunDeb822DoctorCommandFormatsText(t *testing.T) {
	t.Setenv(
		"CROSS_SUITE_DEB822_AUDIT_PATH",
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	got, err := RunDeb822DoctorCommand(
		doctorAdapterFacts(),
		"docker-ce",
		Deb822DoctorOutputFormatText,
	)
	if err != nil {
		t.Fatalf("RunDeb822DoctorCommand() error = %v", err)
	}

	if got.ExitCode != repohealer.Deb822DoctorExitWarning {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.Deb822DoctorExitWarning,
		)
	}
	if got.Report.Overall != repohealer.Deb822DoctorStatusWarning {
		t.Fatalf(
			"overall = %q, want %q",
			got.Report.Overall,
			repohealer.Deb822DoctorStatusWarning,
		)
	}
	if !strings.Contains(got.Output, "Repo Healer Deb822 Readiness Report") {
		t.Fatalf("text output did not contain Doctor heading:\n%s", got.Output)
	}
	if !strings.Contains(got.Output, "Overall: WARNING") {
		t.Fatalf("text output did not contain warning status:\n%s", got.Output)
	}
}

func TestRunDeb822DoctorCommandFormatsJSON(t *testing.T) {
	t.Setenv(
		"CROSS_SUITE_DEB822_AUDIT_PATH",
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	got, err := RunDeb822DoctorCommand(
		doctorAdapterFacts(),
		"docker-ce",
		Deb822DoctorOutputFormatJSON,
	)
	if err != nil {
		t.Fatalf("RunDeb822DoctorCommand() error = %v", err)
	}

	var report repohealer.Deb822DoctorReport
	if err := json.Unmarshal([]byte(got.Output), &report); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if report.Overall != got.Report.Overall {
		t.Fatalf(
			"JSON overall = %q, want %q",
			report.Overall,
			got.Report.Overall,
		)
	}
	if report.ProfileID != "docker-ce" {
		t.Fatalf("JSON profile ID = %q, want docker-ce", report.ProfileID)
	}
	if got.ExitCode != repohealer.Deb822DoctorExitWarning {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.Deb822DoctorExitWarning,
		)
	}
}

func TestRunDeb822DoctorCommandRejectsUnknownFormat(t *testing.T) {
	t.Setenv(
		"CROSS_SUITE_DEB822_AUDIT_PATH",
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	got, err := RunDeb822DoctorCommand(
		doctorAdapterFacts(),
		"docker-ce",
		Deb822DoctorOutputFormat("yaml"),
	)
	if err == nil {
		t.Fatalf(
			"RunDeb822DoctorCommand() unexpectedly succeeded: %#v",
			got,
		)
	}
	if got.ExitCode != repohealer.Deb822DoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.Deb822DoctorExitUnknown,
		)
	}
}
