package repohealer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func readyAPTListDoctorProbe() APTListDoctorRemoteProbe {
	return APTListDoctorRemoteProbe{
		APTAvailable: true,
		GPGAvailable: true,
		Source: APTListDoctorRemoteFile{
			State: APTListDoctorFileStatePresent,
			Mode:  "644",
			Size:  120,
		},
		Keyring: APTListDoctorRemoteFile{
			State: APTListDoctorFileStatePresent,
			Mode:  "644",
			Size:  240,
		},
		KeyringFingerprints: []string{
			HashiCorpAPTListExpectedFingerprint,
		},
	}
}

func aptListDoctorFacts() TargetFacts {
	return TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "6.4",
		Codename:       "lory",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}
}

func TestDiagnoseSelectedAPTListRepairRemoteReadiness(t *testing.T) {
	action := aptListDoctorProbeAction()
	facts := aptListDoctorFacts()

	tests := []struct {
		name           string
		mutate         func(*APTListDoctorRemoteProbe)
		wantOverall    APTListDoctorStatus
		wantInspect    bool
		wantPreview    bool
		wantApply      bool
		wantCheck      string
		wantCheckState APTListDoctorStatus
	}{
		{
			name:        "Ready metadata",
			mutate:      func(*APTListDoctorRemoteProbe) {},
			wantOverall: APTListDoctorStatusReady,
			wantInspect: false,
			wantPreview: false,
			wantApply:   false,
		},
		{
			name: "Missing expected HashiCorp key blocks",
			mutate: func(probe *APTListDoctorRemoteProbe) {
				probe.KeyringFingerprints = nil
			},
			wantOverall:    APTListDoctorStatusBlocked,
			wantInspect:    false,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "expected_signing_key",
			wantCheckState: APTListDoctorStatusBlocked,
		},
		{
			name: "Missing source blocks",
			mutate: func(probe *APTListDoctorRemoteProbe) {
				probe.Source.State = APTListDoctorFileStateMissing
				probe.Source.Mode = ""
				probe.Source.Size = 0
			},
			wantOverall:    APTListDoctorStatusBlocked,
			wantInspect:    false,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_source_file",
			wantCheckState: APTListDoctorStatusBlocked,
		},
		{
			name: "Unsafe keyring mode blocks",
			mutate: func(probe *APTListDoctorRemoteProbe) {
				probe.Keyring.State = APTListDoctorFileStateUnsafeMode
			},
			wantOverall:    APTListDoctorStatusBlocked,
			wantInspect:    false,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_keyring_file",
			wantCheckState: APTListDoctorStatusBlocked,
		},
		{
			name: "Missing apt-get blocks",
			mutate: func(probe *APTListDoctorRemoteProbe) {
				probe.APTAvailable = false
			},
			wantOverall:    APTListDoctorStatusBlocked,
			wantInspect:    false,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_apt_get",
			wantCheckState: APTListDoctorStatusBlocked,
		},
		{
			name: "Missing gpg blocks",
			mutate: func(probe *APTListDoctorRemoteProbe) {
				probe.GPGAvailable = false
			},
			wantOverall:    APTListDoctorStatusBlocked,
			wantInspect:    false,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_gpg",
			wantCheckState: APTListDoctorStatusBlocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := readyAPTListDoctorProbe()
			test.mutate(&probe)

			got := DiagnoseSelectedAPTListRepairRemoteReadiness(
				facts,
				action,
				probe,
			)

			if got.Overall != test.wantOverall {
				t.Fatalf(
					"overall = %q, want %q; checks = %#v",
					got.Overall,
					test.wantOverall,
					got.Checks,
				)
			}
			if got.CanInspect != test.wantInspect ||
				got.CanPreview != test.wantPreview ||
				got.CanApply != test.wantApply {
				t.Fatalf(
					"permissions = inspect:%t preview:%t apply:%t",
					got.CanInspect,
					got.CanPreview,
					got.CanApply,
				)
			}

			if test.wantCheck == "" {
				return
			}

			for _, check := range got.Checks {
				if check.Name == test.wantCheck &&
					check.Status == test.wantCheckState {
					return
				}
			}

			t.Fatalf(
				"missing check %q with status %q: %#v",
				test.wantCheck,
				test.wantCheckState,
				got.Checks,
			)
		})
	}
}

func TestDiagnoseSelectedAPTListRepairRemoteReadinessRejectsUnsupportedTarget(
	t *testing.T,
) {
	facts := aptListDoctorFacts()
	facts.PackageManager = ManagerUnknown

	got := DiagnoseSelectedAPTListRepairRemoteReadiness(
		facts,
		aptListDoctorProbeAction(),
		readyAPTListDoctorProbe(),
	)

	if got.Overall != APTListDoctorStatusUnsupported {
		t.Fatalf("overall = %q, want unsupported", got.Overall)
	}
	if got.CanInspect || got.CanPreview || got.CanApply {
		t.Fatalf("unsupported report permissions = %#v", got)
	}
}

func TestRunSelectedAPTListDoctorRemoteServiceFormatsBlockedResult(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"120",
				"present",
				"644",
				"240",
			),
		},
	}

	got, err := RunSelectedAPTListDoctorRemoteService(
		exec,
		aptListDoctorFacts(),
		aptListDoctorProbeAction(),
	)
	if err != nil {
		t.Fatalf("RunSelectedAPTListDoctorRemoteService() error = %v", err)
	}

	if got.Report.Overall != APTListDoctorStatusBlocked {
		t.Fatalf("overall = %q, want blocked", got.Report.Overall)
	}
	if got.ExitCode != APTListDoctorExitBlocked {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			APTListDoctorExitBlocked,
		)
	}
	if !strings.Contains(
		string(got.JSON),
		`"overall":"blocked"`,
	) {
		t.Fatalf("JSON = %s", got.JSON)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(exec.commands))
	}
}

func TestRunSelectedAPTListDoctorRemoteServiceReportsUnknownProbeFailure(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelErrors: []error{errors.New("ssh transport failed")},
	}

	got, err := RunSelectedAPTListDoctorRemoteService(
		exec,
		aptListDoctorFacts(),
		aptListDoctorProbeAction(),
	)
	if err != nil {
		t.Fatalf("RunSelectedAPTListDoctorRemoteService() error = %v", err)
	}

	if got.Report.Overall != APTListDoctorStatusUnknown {
		t.Fatalf("overall = %q, want unknown", got.Report.Overall)
	}
	if got.ExitCode != APTListDoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			APTListDoctorExitUnknown,
		)
	}
	if !strings.Contains(string(got.JSON), `"overall":"unknown"`) {
		t.Fatalf("JSON = %s", got.JSON)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(exec.commands))
	}
}

func TestRunSelectedAPTListDoctorRemoteServiceJSONRoundTrip(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"120",
				"present",
				"644",
				"240",
				HashiCorpAPTListExpectedFingerprint,
			),
		},
	}

	got, err := RunSelectedAPTListDoctorRemoteService(
		exec,
		aptListDoctorFacts(),
		aptListDoctorProbeAction(),
	)
	if err != nil {
		t.Fatalf("RunSelectedAPTListDoctorRemoteService() error = %v", err)
	}

	var decoded APTListDoctorReport
	if err := json.Unmarshal(got.JSON, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.Overall != APTListDoctorStatusReady {
		t.Fatalf("decoded overall = %q, want ready", decoded.Overall)
	}
	if decoded.ActionID != aptListDoctorProbeAction().ID {
		t.Fatalf("decoded action ID = %q", decoded.ActionID)
	}
	if decoded.CanInspect || decoded.CanPreview || decoded.CanApply {
		t.Fatalf("decoded permissions = %#v", decoded)
	}
}
