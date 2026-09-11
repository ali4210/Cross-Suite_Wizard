package repohealer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnoseDeb822RepairReadinessReadyForKnownProfile(t *testing.T) {
	auditPath := filepath.Join(
		t.TempDir(),
		"state",
		"cross-suite",
		"repohealer-deb822-audit.jsonl",
	)
	t.Setenv(deb822RepairAuditPathEnv, auditPath)
	t.Setenv(deb822RepairExecutionEnabledEnv, "true")

	report := DiagnoseDeb822RepairReadiness(
		TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		"docker-ce",
	)

	if report.Overall != Deb822DoctorStatusWarning {
		t.Fatalf(
			"overall = %q, want %q",
			report.Overall,
			Deb822DoctorStatusWarning,
		)
	}
	if !report.CanPreview {
		t.Fatal("can preview = false, want true")
	}
	if !report.CanApply {
		t.Fatal("can apply = false, want true")
	}
	if report.AuditPath != auditPath {
		t.Fatalf("audit path = %q, want %q", report.AuditPath, auditPath)
	}
}

func TestDiagnoseDeb822RepairReadinessWarnsWhenPolicyDisabled(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)
	t.Setenv(deb822RepairExecutionEnabledEnv, "")

	report := DiagnoseDeb822RepairReadiness(
		TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		"docker-ce",
	)

	if report.Overall != Deb822DoctorStatusWarning {
		t.Fatalf("overall = %q, want %q", report.Overall, Deb822DoctorStatusWarning)
	}
	if !report.CanPreview {
		t.Fatal("can preview = false, want true")
	}
	if report.CanApply {
		t.Fatal("can apply = true, want false")
	}
}

func TestDiagnoseDeb822RepairReadinessRejectsUnsupportedTarget(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	report := DiagnoseDeb822RepairReadiness(
		TargetFacts{
			Platform:       PlatformWindows,
			PackageManager: ManagerWinget,
		},
		"docker-ce",
	)

	if report.Overall != Deb822DoctorStatusUnsupported {
		t.Fatalf(
			"overall = %q, want %q",
			report.Overall,
			Deb822DoctorStatusUnsupported,
		)
	}
	if report.CanPreview {
		t.Fatal("can preview = true, want false")
	}
	if report.CanApply {
		t.Fatal("can apply = true, want false")
	}
}

func TestDiagnoseDeb822RepairReadinessRejectsUnknownProfile(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	report := DiagnoseDeb822RepairReadiness(
		TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		"unknown-profile",
	)

	if report.Overall != Deb822DoctorStatusUnsupported {
		t.Fatalf(
			"overall = %q, want %q",
			report.Overall,
			Deb822DoctorStatusUnsupported,
		)
	}
	if report.CanPreview {
		t.Fatal("can preview = true, want false")
	}
}

func TestCheckDeb822AuditPathWritableCreatesAndCleansProbe(t *testing.T) {
	auditPath := filepath.Join(
		t.TempDir(),
		"state",
		"cross-suite",
		"repohealer-deb822-audit.jsonl",
	)
	parent := filepath.Dir(auditPath)

	if err := checkDeb822AuditPathWritable(auditPath); err != nil {
		t.Fatalf("checkDeb822AuditPathWritable() error = %v", err)
	}

	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("audit parent directory was not created: %v", err)
	}

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("audit path probe left entries behind: %#v", entries)
	}
}

func TestFormatDeb822DoctorReport(t *testing.T) {
	report := Deb822DoctorReport{
		Overall:    Deb822DoctorStatusWarning,
		ProfileID:  "docker-ce",
		AuditPath:  "/tmp/repohealer-audit.jsonl",
		CanPreview: true,
		CanApply:   false,
		Checks: []Deb822DoctorCheck{
			{
				Name:    "execution_policy",
				Status:  Deb822DoctorStatusWarning,
				Message: "execution policy is disabled",
			},
		},
	}

	got := FormatDeb822DoctorReport(report)

	for _, want := range []string{
		"Repo Healer Deb822 Readiness Report",
		"Overall: WARNING",
		"Can preview: true",
		"Can apply: false",
		"Profile: docker-ce",
		"[WARNING] execution_policy: execution policy is disabled",
		"Doctor is read-only",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted report missing %q:\n%s", want, got)
		}
	}
}

func TestDiagnoseDeb822RepairReadinessDoesNotTreatLegacyProfilePathAsDeb822Path(t *testing.T) {
	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)
	t.Setenv(deb822RepairExecutionEnabledEnv, "true")

	report := DiagnoseDeb822RepairReadiness(
		TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		"docker-ce",
	)

	var sourceCheck Deb822DoctorCheck
	found := false
	for _, check := range report.Checks {
		if check.Name == "source_path" {
			sourceCheck = check
			found = true
			break
		}
	}
	if !found {
		t.Fatal("source_path check was not present")
	}

	if sourceCheck.Status != Deb822DoctorStatusWarning {
		t.Fatalf(
			"source_path status = %q, want %q",
			sourceCheck.Status,
			Deb822DoctorStatusWarning,
		)
	}
	if strings.Contains(sourceCheck.Message, "docker.list") {
		t.Fatalf(
			"Deb822 Doctor must not advertise legacy profile path: %q",
			sourceCheck.Message,
		)
	}
	if !strings.Contains(sourceCheck.Message, "supported detected repair action") {
		t.Fatalf(
			"source_path message = %q, want action-bound validation guidance",
			sourceCheck.Message,
		)
	}
}

func TestDiagnoseSelectedDeb822RepairReadiness(t *testing.T) {
	baseAction := RepairAction{
		ID:                 "apt-source-binding-repair-docker-ce",
		FindingCode:        "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:          "docker-ce",
		ProfileDisplayName: "Docker CE",
		RepositoryURL:      "https://download.docker.com/linux/debian",
		SourceFile:         "/etc/apt/sources.list.d/docker.sources",
		SourceFormat:       SourceFormatDeb822,
		KeyringPath:        "/etc/apt/keyrings/docker.gpg",
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
	}

	tests := []struct {
		name       string
		mutate     func(*RepairAction)
		wantStatus Deb822DoctorStatus
		wantCheck  string
	}{
		{
			name:       "Ready action",
			mutate:     func(*RepairAction) {},
			wantStatus: Deb822DoctorStatusReady,
		},
		{
			name: "Non Deb822 format",
			mutate: func(action *RepairAction) {
				action.SourceFormat = SourceFormatAPTList
			},
			wantStatus: Deb822DoctorStatusUnsupported,
			wantCheck:  "action_source_format",
		},
		{
			name: "Unsafe source path",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/tmp/docker.sources"
			},
			wantStatus: Deb822DoctorStatusBlocked,
			wantCheck:  "action_source_path",
		},
		{
			name: "Wrong keyring",
			mutate: func(action *RepairAction) {
				action.KeyringPath = "/etc/apt/keyrings/other.gpg"
			},
			wantStatus: Deb822DoctorStatusBlocked,
			wantCheck:  "action_keyring_binding",
		},
		{
			name: "Wrong repository",
			mutate: func(action *RepairAction) {
				action.RepositoryURL = "https://example.invalid/not-docker"
			},
			wantStatus: Deb822DoctorStatusBlocked,
			wantCheck:  "action_repository_binding",
		},
		{
			name: "Incomplete action",
			mutate: func(action *RepairAction) {
				action.ID = ""
			},
			wantStatus: Deb822DoctorStatusBlocked,
			wantCheck:  "action_binding",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := baseAction
			test.mutate(&action)

			t.Setenv(
				deb822RepairAuditPathEnv,
				filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
			)
			t.Setenv(deb822RepairExecutionEnabledEnv, "true")

			report := DiagnoseSelectedDeb822RepairReadiness(
				baseAction.Target,
				action,
			)

			if report.Overall != test.wantStatus {
				t.Fatalf(
					"overall = %q, want %q; checks = %#v",
					report.Overall,
					test.wantStatus,
					report.Checks,
				)
			}

			if test.wantCheck == "" {
				if !report.CanPreview {
					t.Fatal("ready action must allow preview")
				}
				if !report.CanApply {
					t.Fatal("ready action must allow apply when policy is enabled")
				}
				return
			}

			if report.CanApply {
				t.Fatalf(
					"unsafe action must not allow apply: %#v",
					report,
				)
			}

			found := false
			for _, check := range report.Checks {
				if check.Name == test.wantCheck &&
					(check.Status == Deb822DoctorStatusBlocked ||
						check.Status == Deb822DoctorStatusUnsupported) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf(
					"missing expected blocking check %q: %#v",
					test.wantCheck,
					report.Checks,
				)
			}
		})
	}
}

func TestDiagnoseSelectedDeb822RepairReadinessRejectsTargetMismatch(t *testing.T) {
	action := RepairAction{
		ID:            "apt-source-binding-repair-docker-ce",
		FindingCode:   "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:     "docker-ce",
		RepositoryURL: "https://download.docker.com/linux/debian",
		SourceFile:    "/etc/apt/sources.list.d/docker.sources",
		SourceFormat:  SourceFormatDeb822,
		KeyringPath:   "/etc/apt/keyrings/docker.gpg",
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
	}

	facts := action.Target
	facts.Architecture = "arm64"

	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)

	report := DiagnoseSelectedDeb822RepairReadiness(facts, action)

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
}

func TestDiagnoseSelectedDeb822RepairReadinessReplacesGenericSourcePathWarning(t *testing.T) {
	action := RepairAction{
		ID:            "apt-source-binding-repair-docker-ce",
		FindingCode:   "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:     "docker-ce",
		RepositoryURL: "https://download.docker.com/linux/debian",
		SourceFile:    "/etc/apt/sources.list.d/docker.sources",
		SourceFormat:  SourceFormatDeb822,
		KeyringPath:   "/etc/apt/keyrings/docker.gpg",
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
	}

	t.Setenv(
		deb822RepairAuditPathEnv,
		filepath.Join(t.TempDir(), "repohealer-audit.jsonl"),
	)
	t.Setenv(deb822RepairExecutionEnabledEnv, "true")

	report := DiagnoseSelectedDeb822RepairReadiness(action.Target, action)

	for _, check := range report.Checks {
		if check.Name == "source_path" {
			t.Fatalf(
				"generic source_path warning must be removed for selected action: %#v",
				check,
			)
		}
	}

	foundActionPath := false
	for _, check := range report.Checks {
		if check.Name == "action_source_path" &&
			check.Status == Deb822DoctorStatusReady {
			foundActionPath = true
			break
		}
	}
	if !foundActionPath {
		t.Fatalf(
			"action-bound source path ready check missing: %#v",
			report.Checks,
		)
	}
}
