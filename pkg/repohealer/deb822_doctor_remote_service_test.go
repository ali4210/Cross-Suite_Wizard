package repohealer

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func remoteDoctorServiceFacts() TargetFacts {
	return TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}
}

func TestRunSelectedDeb822DoctorRemoteServiceReturnsReadyReportJSONAndExitCode(
	t *testing.T,
) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	action := doctorProbeAction()
	action.Target = remoteDoctorServiceFacts()

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			doctorProbeOutput(
				"present",
				"present",
				"644",
				"180",
				"present",
				"644",
				"32",
				"clear",
			),
		},
	}

	got, err := RunSelectedDeb822DoctorRemoteService(
		exec,
		action.Target,
		action,
	)
	if err != nil {
		t.Fatalf("RunSelectedDeb822DoctorRemoteService() error = %v", err)
	}

	if got.Report.Overall != Deb822DoctorStatusWarning {
		t.Fatalf(
			"overall = %q, want %q",
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
	if !got.Report.CanPreview {
		t.Fatal("ready remote metadata must permit preview")
	}
	if got.Report.CanApply {
		t.Fatal("apply must remain unavailable while execution policy is disabled")
	}

	var decoded Deb822DoctorReport
	if err := json.Unmarshal(got.JSON, &decoded); err != nil {
		t.Fatalf("remote Doctor JSON is invalid: %v", err)
	}
	if decoded.Overall != got.Report.Overall ||
		decoded.Target != got.Report.Target ||
		decoded.ProfileID != got.Report.ProfileID ||
		decoded.CanPreview != got.Report.CanPreview ||
		decoded.CanApply != got.Report.CanApply {
		t.Fatalf("decoded report = %#v, want %#v", decoded, got.Report)
	}

	if len(exec.commands) != 1 {
		t.Fatalf(
			"remote Doctor command count = %d, want metadata probe only: %#v",
			len(exec.commands),
			exec.commands,
		)
	}
}

func TestRunSelectedDeb822DoctorRemoteServiceReturnsBlockedReportOnProbeFailure(
	t *testing.T,
) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	action := doctorProbeAction()
	action.Target = remoteDoctorServiceFacts()

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			"not a valid remote Doctor probe response",
		},
	}

	got, err := RunSelectedDeb822DoctorRemoteService(
		exec,
		action.Target,
		action,
	)
	if err != nil {
		t.Fatalf(
			"RunSelectedDeb822DoctorRemoteService() error = %v, want report result",
			err,
		)
	}

	if got.Report.Overall != Deb822DoctorStatusBlocked {
		t.Fatalf(
			"overall = %q, want %q",
			got.Report.Overall,
			Deb822DoctorStatusBlocked,
		)
	}
	if got.ExitCode != Deb822DoctorExitBlocked {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			Deb822DoctorExitBlocked,
		)
	}
	if got.Report.CanPreview {
		t.Fatal("failed remote metadata probe must block preview")
	}
	if got.Report.CanApply {
		t.Fatal("failed remote metadata probe must block apply")
	}
	if len(exec.commands) != 1 {
		t.Fatalf(
			"remote Doctor command count = %d, want metadata probe only: %#v",
			len(exec.commands),
			exec.commands,
		)
	}
}
