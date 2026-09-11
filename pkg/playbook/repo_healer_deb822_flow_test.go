package playbook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cross-ssh/pkg/repohealer"
)

func blockedDockerDeb822PlaybookAction() repohealer.RepairAction {
	return repohealer.RepairAction{
		ID:                 "apt-source-binding-repair-docker-ce",
		FindingCode:        "APT_SOURCE_KEYRING_MISMATCH",
		ProfileID:          "docker-ce",
		ProfileDisplayName: "Docker CE",
		RepositoryURL:      "https://download.docker.com/linux/debian",
		SourceFile:         "/etc/apt/sources.list.d/docker.sources",
		SourceLine:         1,
		SourceFormat:       repohealer.SourceFormatDeb822,
		Eligible:           false,
		RequiresConsent:    false,
		Target: repohealer.TargetFacts{
			Platform:       repohealer.PlatformLinux,
			Distribution:   "debian",
			Version:        "12",
			Codename:       "bookworm",
			Architecture:   "amd64",
			PackageManager: repohealer.ManagerAPT,
		},
		KeyringPath: "/etc/apt/keyrings/docker.gpg",
	}
}

func readyDockerDeb822PlaybookInspection(
	action repohealer.RepairAction,
) repohealer.Deb822RepairInspection {
	return repohealer.Deb822RepairInspection{
		ActionID:    action.ID,
		ProfileID:   action.ProfileID,
		ProfileName: action.ProfileDisplayName,
		SourceFile:  action.SourceFile,
		KeyringPath: action.KeyringPath,
		SnapshotTargets: []string{
			action.SourceFile,
			action.KeyringPath,
		},
		RenderedSource: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`,
		Ready: true,
	}
}

func TestPrepareSelectedDeb822RepairExecutionBuildsBoundRequest(t *testing.T) {
	action := blockedDockerDeb822PlaybookAction()
	inspection := readyDockerDeb822PlaybookInspection(action)

	got, err := prepareSelectedDeb822RepairExecution(action, inspection)
	if err != nil {
		t.Fatalf("prepareSelectedDeb822RepairExecution() error = %v", err)
	}

	if got.ActionID != action.ID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, action.ID)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.KeyringPath != action.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, action.KeyringPath)
	}
	if got.RenderedSource != inspection.RenderedSource {
		t.Fatalf("rendered source = %q, want %q", got.RenderedSource, inspection.RenderedSource)
	}
}

func TestPrepareSelectedDeb822RepairExecutionRejectsUnsafeInputs(t *testing.T) {
	baseAction := blockedDockerDeb822PlaybookAction()
	baseInspection := readyDockerDeb822PlaybookInspection(baseAction)

	tests := []struct {
		name       string
		mutate     func(*repohealer.RepairAction, *repohealer.Deb822RepairInspection)
		wantReason string
	}{
		{
			name: "Eligible action",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				action.Eligible = true
			},
			wantReason: "not an original blocked Deb822 action",
		},
		{
			name: "Consent-bearing action",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				action.RequiresConsent = true
			},
			wantReason: "not an original blocked Deb822 action",
		},
		{
			name: "Non-Deb822 action",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				action.SourceFormat = repohealer.SourceFormatAPTList
			},
			wantReason: "not an original blocked Deb822 action",
		},
		{
			name: "Unknown profile",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				action.ProfileID = "unknown"
				inspection.ProfileID = "unknown"
			},
			wantReason: "does not resolve to its verified APT vendor profile",
		},
		{
			name: "Inspection not ready",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				inspection.Ready = false
			},
			wantReason: "inspection is not ready",
		},
		{
			name: "Rendered source mismatch",
			mutate: func(
				action *repohealer.RepairAction,
				inspection *repohealer.Deb822RepairInspection,
			) {
				inspection.RenderedSource = strings.Replace(
					inspection.RenderedSource,
					"Signed-By: /etc/apt/keyrings/docker.gpg",
					"Signed-By: /etc/apt/keyrings/other.gpg",
					1,
				)
			},
			wantReason: "inspection rendered replacement source is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := baseAction
			inspection := baseInspection
			inspection.SnapshotTargets = append(
				[]string(nil),
				baseInspection.SnapshotTargets...,
			)

			test.mutate(&action, &inspection)

			got, err := prepareSelectedDeb822RepairExecution(action, inspection)
			if err == nil {
				t.Fatalf(
					"prepareSelectedDeb822RepairExecution() unexpectedly succeeded: %#v",
					got,
				)
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
		})
	}
}

func TestAppendDeb822RepairAuditWritesBlockedDecision(t *testing.T) {
	auditPath := filepath.Join(
		t.TempDir(),
		"state",
		"cross-suite",
		"repohealer-deb822-audit.jsonl",
	)

	audit := repohealer.BuildDeb822RepairAuditEvent(
		repohealer.Deb822RepairApprovalResult{
			Status:      repohealer.Deb822RepairApprovalStatusBlocked,
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			Reason:      "SECRET_POLICY_REASON_DO_NOT_LOG",
		},
		time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC),
	)

	if err := appendDeb822RepairAudit(auditPath, audit); err != nil {
		t.Fatalf("appendDeb822RepairAudit() error = %v", err)
	}

	content, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	var event repohealer.Deb822RepairAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(content), &event); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if event.Status != repohealer.Deb822RepairApprovalStatusBlocked {
		t.Fatalf(
			"status = %q, want %q",
			event.Status,
			repohealer.Deb822RepairApprovalStatusBlocked,
		)
	}
	if event.FailureCategory != repohealer.RepairFailureBlocked {
		t.Fatalf(
			"failure category = %q, want %q",
			event.FailureCategory,
			repohealer.RepairFailureBlocked,
		)
	}
	if strings.Contains(string(content), "SECRET_POLICY_REASON_DO_NOT_LOG") {
		t.Fatalf(
			"audit content must not contain raw reason: %s",
			content,
		)
	}
}

func TestShouldContinueDeb822RepairAfterPreviewRequiresExplicitApplyMode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "Empty defaults to preview exit", input: "", want: false},
		{name: "Whitespace defaults to preview exit", input: " ", want: false},
		{name: "Preview defaults to preview exit", input: "p", want: false},
		{name: "Cancel defaults to preview exit", input: "q", want: false},
		{name: "No defaults to preview exit", input: "no", want: false},
		{name: "Yes does not skip apply mode", input: "yes", want: false},
		{name: "Long apply does not bypass exact mode", input: "apply", want: false},
		{name: "Exact apply mode", input: "a", want: true},
		{name: "Uppercase apply mode", input: "A", want: true},
		{name: "Trimmed apply mode", input: "  a  ", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldContinueDeb822RepairAfterPreview(test.input); got != test.want {
				t.Fatalf(
					"shouldContinueDeb822RepairAfterPreview(%q) = %t, want %t",
					test.input,
					got,
					test.want,
				)
			}
		})
	}
}

func TestDeb822PreviewDefaultDoesNotEnterApplyMode(t *testing.T) {
	if shouldContinueDeb822RepairAfterPreview("") {
		t.Fatal(
			"empty preview response must exit without entering apply confirmation",
		)
	}

	if shouldContinueDeb822RepairAfterPreview("yes") {
		t.Fatal(
			"approval text must not bypass explicit preview-to-apply selection",
		)
	}
}
