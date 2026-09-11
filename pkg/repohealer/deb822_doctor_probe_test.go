package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func doctorProbeOutput(
	aptGet string,
	sourceState string,
	sourceMode string,
	sourceSize string,
	keyringState string,
	keyringMode string,
	keyringSize string,
	locks string,
) string {
	return strings.Join([]string{
		deb822DoctorProbeBegin,
		"apt_get|" + aptGet,
		"file|source|" + sourceState + "|" + sourceMode + "|" + sourceSize,
		"file|keyring|" + keyringState + "|" + keyringMode + "|" + keyringSize,
		"locks|" + locks,
		deb822DoctorProbeEnd,
	}, "\n")
}

func doctorProbeAction() RepairAction {
	return RepairAction{
		ID:            "apt-source-binding-repair-docker-ce",
		FindingCode:   "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:     "docker-ce",
		RepositoryURL: "https://download.docker.com/linux/debian",
		SourceFile:    "/etc/apt/sources.list.d/docker.sources",
		SourceFormat:  SourceFormatDeb822,
		KeyringPath:   "/etc/apt/keyrings/docker.gpg",
	}
}

func TestProbeSelectedDeb822RepairMetadataReturnsReadOnlyMetadata(t *testing.T) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			doctorProbeOutput(
				"present",
				"present",
				"644",
				"123",
				"missing",
				"",
				"",
				"clear",
			),
		},
	}

	got, err := ProbeSelectedDeb822RepairMetadata(exec, doctorProbeAction())
	if err != nil {
		t.Fatalf("ProbeSelectedDeb822RepairMetadata() error = %v", err)
	}

	if !got.APTAvailable {
		t.Fatal("APTAvailable = false, want true")
	}
	if got.Source.State != Deb822DoctorFileStatePresent {
		t.Fatalf("source state = %q", got.Source.State)
	}
	if got.Source.Mode != "644" || got.Source.Size != 123 {
		t.Fatalf("source metadata = %#v", got.Source)
	}
	if got.Keyring.State != Deb822DoctorFileStateMissing {
		t.Fatalf("keyring state = %q", got.Keyring.State)
	}
	if got.PackageLocksActive {
		t.Fatal("PackageLocksActive = true, want false")
	}

	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(exec.commands))
	}

	command := exec.commands[0]
	if !strings.Contains(
		command,
		"SUDO_LABEL["+deb822DoctorProbeLabel+"]: ",
	) {
		t.Fatalf("probe label missing from command: %s", command)
	}
	for _, expected := range []string{
		`SOURCE_FILE="/etc/apt/sources.list.d/docker.sources"`,
		`KEYRING_PATH="/etc/apt/keyrings/docker.gpg"`,
		"stat -c",
		"command -v apt-get",
		"fuser /var/lib/dpkg/lock-frontend",
		deb822DoctorProbeBegin,
		deb822DoctorProbeEnd,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("probe command missing %q:\n%s", expected, command)
		}
	}
	if !strings.Contains(command, ">/dev/null 2>&1") {
		t.Fatalf("probe command must suppress non-protocol command output: %s", command)
	}

	for _, forbidden := range []string{
		"apt-get update",
		"apt-get install",
		"curl ",
		"wget ",
		"gpg ",
		"mv ",
		"cp ",
		"rm ",
		"chmod ",
		"chown ",
		"touch ",
		"mkdir ",
		"mktemp",
		"base64 --",
		"cat ",
		"> /etc/",
		"> /var/",
		"> /tmp/",
		"> ./",
	} {
		if strings.Contains(command, forbidden) {
			t.Fatalf(
				"probe command must not contain %q:\n%s",
				forbidden,
				command,
			)
		}
	}
}

func TestProbeSelectedDeb822RepairMetadataReportsActiveLocks(t *testing.T) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			doctorProbeOutput(
				"present",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
				"active",
			),
		},
	}

	got, err := ProbeSelectedDeb822RepairMetadata(exec, doctorProbeAction())
	if err != nil {
		t.Fatalf("ProbeSelectedDeb822RepairMetadata() error = %v", err)
	}
	if !got.PackageLocksActive {
		t.Fatal("PackageLocksActive = false, want true")
	}
}

func TestProbeSelectedDeb822RepairMetadataRejectsUnsafeActionWithoutCommand(t *testing.T) {
	action := doctorProbeAction()
	action.SourceFile = "/tmp/docker.sources"

	exec := &fakeExecutor{}
	_, err := ProbeSelectedDeb822RepairMetadata(exec, action)

	if err == nil {
		t.Fatal("unsafe action unexpectedly started remote probe")
	}
	if !strings.Contains(err.Error(), "outside /etc/apt/sources.list.d") {
		t.Fatalf("error = %q", err)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unsafe action issued commands: %#v", exec.commands)
	}
}

func TestProbeSelectedDeb822RepairMetadataRejectsMalformedOutput(t *testing.T) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822DoctorProbeBegin + "\napt_get|present\n" + deb822DoctorProbeEnd,
		},
	}

	_, err := ProbeSelectedDeb822RepairMetadata(exec, doctorProbeAction())

	if err == nil {
		t.Fatal("malformed probe output unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "invalid probe output envelope") {
		t.Fatalf("error = %q", err)
	}
}

func TestProbeSelectedDeb822RepairMetadataRejectsTransportFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			doctorProbeOutput(
				"present",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
				"clear",
			),
		},
		runSudoLabelErrors: []error{errors.New("ssh transport failed")},
	}

	_, err := ProbeSelectedDeb822RepairMetadata(exec, doctorProbeAction())

	if err == nil {
		t.Fatal("transport error unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "Deb822 Doctor remote probe failed: ssh transport failed") {
		t.Fatalf("error = %q", err)
	}
}

func TestParseDeb822DoctorProbeOutputRejectsUnsafeRecords(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name: "Unknown record",
			output: strings.Join([]string{
				deb822DoctorProbeBegin,
				"apt_get|present",
				"file|source|present|644|1",
				"file|keyring|present|644|2",
				"locks|clear",
				"extra|value",
				deb822DoctorProbeEnd,
			}, "\n"),
		},
		{
			name: "Duplicate file",
			output: strings.Join([]string{
				deb822DoctorProbeBegin,
				"apt_get|present",
				"file|source|present|644|1",
				"file|source|present|644|1",
				"file|keyring|present|644|2",
				"locks|clear",
				deb822DoctorProbeEnd,
			}, "\n"),
		},
		{
			name: "Unexpected missing metadata",
			output: doctorProbeOutput(
				"present",
				"missing",
				"644",
				"1",
				"present",
				"644",
				"2",
				"clear",
			),
		},
		{
			name: "Invalid file state",
			output: doctorProbeOutput(
				"present",
				"secret_state",
				"",
				"",
				"present",
				"644",
				"2",
				"clear",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDeb822DoctorProbeOutput(test.output)
			if err == nil {
				t.Fatal("unsafe probe record unexpectedly parsed")
			}
		})
	}
}

func TestDiagnoseSelectedDeb822RepairRemoteReadiness(t *testing.T) {
	baseAction := doctorProbeAction()
	baseFacts := TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}
	baseAction.Target = baseFacts

	tests := []struct {
		name           string
		output         string
		wantOverall    Deb822DoctorStatus
		wantPreview    bool
		wantApply      bool
		wantCheck      string
		wantCheckState Deb822DoctorStatus
	}{
		{
			name: "Ready remote metadata",
			output: doctorProbeOutput(
				"present",
				"present",
				"644",
				"100",
				"present",
				"644",
				"200",
				"clear",
			),
			wantOverall: Deb822DoctorStatusReady,
			wantPreview: true,
			wantApply:   true,
		},
		{
			name: "Missing keyring warns",
			output: doctorProbeOutput(
				"present",
				"present",
				"644",
				"100",
				"missing",
				"",
				"",
				"clear",
			),
			wantOverall:    Deb822DoctorStatusWarning,
			wantPreview:    true,
			wantApply:      true,
			wantCheck:      "remote_keyring_file",
			wantCheckState: Deb822DoctorStatusWarning,
		},
		{
			name: "Active locks warn",
			output: doctorProbeOutput(
				"present",
				"present",
				"644",
				"100",
				"present",
				"644",
				"200",
				"active",
			),
			wantOverall:    Deb822DoctorStatusWarning,
			wantPreview:    true,
			wantApply:      true,
			wantCheck:      "remote_package_locks",
			wantCheckState: Deb822DoctorStatusWarning,
		},
		{
			name: "Missing source blocks",
			output: doctorProbeOutput(
				"present",
				"missing",
				"",
				"",
				"present",
				"644",
				"200",
				"clear",
			),
			wantOverall:    Deb822DoctorStatusBlocked,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_source_file",
			wantCheckState: Deb822DoctorStatusBlocked,
		},
		{
			name: "Missing apt blocks",
			output: doctorProbeOutput(
				"missing",
				"present",
				"644",
				"100",
				"present",
				"644",
				"200",
				"clear",
			),
			wantOverall:    Deb822DoctorStatusBlocked,
			wantPreview:    false,
			wantApply:      false,
			wantCheck:      "remote_apt_get",
			wantCheckState: Deb822DoctorStatusBlocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(
				deb822RepairAuditPathEnv,
				t.TempDir()+"/repohealer-audit.jsonl",
			)
			t.Setenv(deb822RepairExecutionEnabledEnv, "true")

			exec := &fakeExecutor{
				runSudoLabelOutputs: []string{test.output},
			}

			report := DiagnoseSelectedDeb822RepairRemoteReadiness(
				exec,
				baseFacts,
				baseAction,
			)

			if report.Overall != test.wantOverall {
				t.Fatalf(
					"overall = %q, want %q; checks = %#v",
					report.Overall,
					test.wantOverall,
					report.Checks,
				)
			}
			if report.CanPreview != test.wantPreview {
				t.Fatalf(
					"can preview = %t, want %t",
					report.CanPreview,
					test.wantPreview,
				)
			}
			if report.CanApply != test.wantApply {
				t.Fatalf(
					"can apply = %t, want %t",
					report.CanApply,
					test.wantApply,
				)
			}

			if test.wantCheck != "" {
				found := false
				for _, check := range report.Checks {
					if check.Name == test.wantCheck &&
						check.Status == test.wantCheckState {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf(
						"missing check %q with status %q: %#v",
						test.wantCheck,
						test.wantCheckState,
						report.Checks,
					)
				}
			}
		})
	}
}

func TestDiagnoseSelectedDeb822RepairRemoteReadinessSkipsProbeWhenLocalDoctorBlocks(t *testing.T) {
	action := doctorProbeAction()
	action.SourceFile = "/tmp/docker.sources"

	facts := TargetFacts{
		Platform:       PlatformLinux,
		PackageManager: ManagerAPT,
	}
	action.Target = facts

	t.Setenv(
		deb822RepairAuditPathEnv,
		t.TempDir()+"/repohealer-audit.jsonl",
	)

	exec := &fakeExecutor{}
	report := DiagnoseSelectedDeb822RepairRemoteReadiness(exec, facts, action)

	if report.Overall != Deb822DoctorStatusBlocked {
		t.Fatalf("overall = %q, want blocked", report.Overall)
	}
	if len(exec.commands) != 0 {
		t.Fatalf(
			"local-blocked Doctor must not issue a remote probe: %#v",
			exec.commands,
		)
	}
}

func TestDiagnoseSelectedDeb822RepairRemoteReadinessBlocksProbeFailure(t *testing.T) {
	action := doctorProbeAction()
	facts := TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}
	action.Target = facts

	t.Setenv(
		deb822RepairAuditPathEnv,
		t.TempDir()+"/repohealer-audit.jsonl",
	)

	exec := &fakeExecutor{
		runSudoLabelErrors: []error{errors.New("ssh transport failed")},
	}

	report := DiagnoseSelectedDeb822RepairRemoteReadiness(exec, facts, action)

	if report.Overall != Deb822DoctorStatusBlocked {
		t.Fatalf(
			"overall = %q, want %q",
			report.Overall,
			Deb822DoctorStatusBlocked,
		)
	}
	if report.CanPreview {
		t.Fatalf("can preview = true, want false: %#v", report)
	}
	if report.CanApply {
		t.Fatalf("can apply = true, want false: %#v", report)
	}

	found := false
	for _, check := range report.Checks {
		if check.Name == "remote_metadata_probe" &&
			check.Status == Deb822DoctorStatusBlocked {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("remote metadata failure check missing: %#v", report.Checks)
	}
}
