package repohealer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func previewIntegrationAction() RepairAction {
	return RepairAction{
		ID:                 "apt-source-binding-repair-docker-ce",
		FindingCode:        "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:          "docker-ce",
		ProfileDisplayName: "Docker CE",
		RepositoryURL:      "https://download.docker.com/linux/debian",
		SourceFile:         "/etc/apt/sources.list.d/docker.sources",
		SourceLine:         1,
		SourceFormat:       SourceFormatDeb822,
		Eligible:           false,
		RequiresConsent:    false,
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		KeyringPath: "/etc/apt/keyrings/docker.gpg",
	}
}

func previewIntegrationSourceDocument() string {
	return `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`
}

func TestDeb822PreviewPipelineRequestsNoTargetMutation(t *testing.T) {
	t.Setenv(deb822RepairAuditPathEnv, filepath.Join(
		t.TempDir(),
		"state",
		"repohealer-deb822-audit.jsonl",
	))

	action := previewIntegrationAction()

	profile, ok := FindVendorProfileByID(ManagerAPT, action.ProfileID)
	if !ok {
		t.Fatalf("vendor profile %q was not found", action.ProfileID)
	}

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
			deb822ReaderOutput(previewIntegrationSourceDocument()),
		},
	}

	doctor := DiagnoseSelectedDeb822RepairRemoteReadiness(
		exec,
		action.Target,
		action,
	)
	if !doctor.CanPreview {
		t.Fatalf(
			"remote Doctor blocked preview: overall=%q checks=%#v",
			doctor.Overall,
			doctor.Checks,
		)
	}
	if doctor.CanApply {
		t.Fatal("apply must remain unavailable while execution policy is disabled")
	}

	inspectionAction := action
	inspectionAction.Eligible = true
	inspectionAction.RequiresConsent = true

	inspection := InspectApprovedDeb822Repair(exec, inspectionAction, profile)
	if !inspection.Ready {
		t.Fatalf(
			"InspectApprovedDeb822Repair() blocked: %s",
			inspection.BlockReason,
		)
	}

	request, err := BuildDeb822RepairExecutionRequest(
		inspection,
		action,
		profile,
	)
	if err != nil {
		t.Fatalf("BuildDeb822RepairExecutionRequest() error = %v", err)
	}

	preview := PreviewDeb822Repair(inspection, request)
	if !preview.Ready {
		t.Fatalf("PreviewDeb822Repair() blocked: %s", preview.Reason)
	}

	if preview.SourceFile != action.SourceFile {
		t.Fatalf(
			"preview source file = %q, want %q",
			preview.SourceFile,
			action.SourceFile,
		)
	}
	if preview.KeyringPath != action.KeyringPath {
		t.Fatalf(
			"preview keyring path = %q, want %q",
			preview.KeyringPath,
			action.KeyringPath,
		)
	}
	if preview.RenderedSource == "" {
		t.Fatal("preview rendered source must not be empty")
	}

	auditPath := Deb822RepairAuditPath()
	event := BuildDeb822RepairPreviewAuditEvent(
		preview,
		time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC),
	)
	if err := AppendDeb822RepairPreviewAuditEvent(auditPath, event); err != nil {
		t.Fatalf("AppendDeb822RepairPreviewAuditEvent() error = %v", err)
	}

	auditContent, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", auditPath, err)
	}

	var recorded Deb822RepairPreviewAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(auditContent), &recorded); err != nil {
		t.Fatalf("preview audit JSON is invalid: %v", err)
	}

	if recorded.Event != "apt_deb822_repository_repair_preview" {
		t.Fatalf("preview audit event = %q", recorded.Event)
	}
	if !recorded.Ready {
		t.Fatalf("preview audit ready = false: %#v", recorded)
	}
	if recorded.ActionID != action.ID {
		t.Fatalf(
			"preview audit action ID = %q, want %q",
			recorded.ActionID,
			action.ID,
		)
	}
	if recorded.ProfileID != action.ProfileID {
		t.Fatalf(
			"preview audit profile ID = %q, want %q",
			recorded.ProfileID,
			action.ProfileID,
		)
	}
	if recorded.SourceFile != action.SourceFile {
		t.Fatalf(
			"preview audit source file = %q, want %q",
			recorded.SourceFile,
			action.SourceFile,
		)
	}
	if recorded.KeyringPath != action.KeyringPath {
		t.Fatalf(
			"preview audit keyring path = %q, want %q",
			recorded.KeyringPath,
			action.KeyringPath,
		)
	}
	if recorded.FailureCategory != "" {
		t.Fatalf(
			"preview audit failure category = %q, want empty",
			recorded.FailureCategory,
		)
	}

	if len(exec.commands) != 2 {
		t.Fatalf(
			"preview pipeline command count = %d, want remote Doctor probe and source read only: %#v",
			len(exec.commands),
			exec.commands,
		)
	}

	if !strings.Contains(
		exec.commands[0],
		"SUDO_LABEL["+deb822DoctorProbeLabel+"]: ",
	) {
		t.Fatalf("first command must be the remote Doctor probe:\n%s", exec.commands[0])
	}
	if !strings.Contains(
		exec.commands[1],
		"SUDO_LABEL[Reading Approved Deb822 APT Source]: ",
	) {
		t.Fatalf("second command must be the approved source reader:\n%s", exec.commands[1])
	}

	for _, command := range exec.commands {
		for _, forbidden := range []string{
			"apt-get update",
			"apt-get install",
			"curl ",
			"wget ",
			"gpg ",
			"gpg --dearmor",
			"mktemp",
			"mv ",
			"cp ",
			"rm ",
			"chmod ",
			"chown ",
			"touch ",
			"mkdir ",
			"createAPTFileSnapshot",
			"snapshot",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf(
					"preview pipeline requested mutation-capable command %q:\n%s",
					forbidden,
					command,
				)
			}
		}
	}

	if !strings.Contains(exec.commands[0], "stat -c") {
		t.Fatalf("Doctor probe must inspect metadata only:\n%s", exec.commands[0])
	}
	if strings.Contains(exec.commands[0], "base64 --") {
		t.Fatalf("Doctor probe must not read source contents:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "base64 --") {
		t.Fatalf("approved source reader must use the framed base64 read:\n%s", exec.commands[1])
	}
}
