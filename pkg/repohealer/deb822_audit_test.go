package repohealer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildDeb822RepairAuditEventForAppliedRepair(t *testing.T) {
	occurredAt := time.Date(
		2026,
		time.September,
		12,
		2,
		10,
		0,
		0,
		time.FixedZone("+06", 6*60*60),
	)

	event := BuildDeb822RepairAuditEvent(
		Deb822RepairApprovalResult{
			Status:      Deb822RepairApprovalStatusApplied,
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			ApplyResult: Deb822RepairApplyResult{
				Attempted: true,
				Applied:   true,
				Snapshot: Snapshot{
					ID:      "apt-test",
					Path:    "/var/lib/cross-suite/snapshots/apt-test",
					Created: true,
				},
			},
		},
		occurredAt,
	)

	if event.Event != "apt_deb822_repository_repair" {
		t.Fatalf("event = %q", event.Event)
	}
	if event.Status != Deb822RepairApprovalStatusApplied {
		t.Fatalf("status = %q", event.Status)
	}
	if event.FailureCategory != RepairFailureNone {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
	if !event.RepairAttempted || !event.Applied || event.RolledBack {
		t.Fatalf("unexpected event state: %#v", event)
	}
	if event.SourceFile != "/etc/apt/sources.list.d/docker.sources" {
		t.Fatalf("source file = %q", event.SourceFile)
	}
	if event.KeyringPath != "/etc/apt/keyrings/docker.gpg" {
		t.Fatalf("keyring path = %q", event.KeyringPath)
	}
	if !event.OccurredAt.Equal(occurredAt.UTC()) {
		t.Fatalf("occurred at = %s, want %s", event.OccurredAt, occurredAt.UTC())
	}
}

func TestBuildDeb822RepairAuditEventClassifiesStates(t *testing.T) {
	tests := []struct {
		name string
		in   Deb822RepairApprovalResult
		want RepairFailureCategory
	}{
		{
			name: "Blocked",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusBlocked,
				Reason: "inspection invalid",
			},
			want: RepairFailureBlocked,
		},
		{
			name: "Declined",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusDeclined,
			},
			want: RepairFailureDeclined,
		},
		{
			name: "Fingerprint failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "DEB822_REPAIR_ERROR|fingerprint_mismatch",
			},
			want: RepairFailureFingerprint,
		},
		{
			name: "Verification failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "post-repair Deb822 APT verification failed",
			},
			want: RepairFailureVerification,
		},
		{
			name: "Snapshot failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "could not create targeted APT snapshot",
			},
			want: RepairFailureSnapshot,
		},
		{
			name: "Rollback failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "targeted Deb822 rollback also failed",
			},
			want: RepairFailureRollback,
		},
		{
			name: "Generic execution failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "key download command failed",
			},
			want: RepairFailureExecution,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := BuildDeb822RepairAuditEvent(test.in, time.Now())
			if event.FailureCategory != test.want {
				t.Fatalf(
					"failure category = %q, want %q",
					event.FailureCategory,
					test.want,
				)
			}
		})
	}
}

func TestDeb822RepairAuditEventJSONDoesNotContainRawExecutionData(t *testing.T) {
	event := BuildDeb822RepairAuditEvent(
		Deb822RepairApprovalResult{
			Status:      Deb822RepairApprovalStatusFailed,
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			Reason:      "SECRET_REASON_DO_NOT_LOG",
			ApplyResult: Deb822RepairApplyResult{
				Attempted:       true,
				Output:          "SECRET_MUTATION_OUTPUT_DO_NOT_LOG",
				VerificationOut: "SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
			},
		},
		time.Now(),
	)

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	text := string(encoded)
	for _, forbidden := range []string{
		"SECRET_REASON_DO_NOT_LOG",
		"SECRET_MUTATION_OUTPUT_DO_NOT_LOG",
		"SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
		"RenderedSource",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("audit JSON must not contain %q: %s", forbidden, text)
		}
	}
}

func TestAppendDeb822RepairAuditEventCreatesJSONLAndAppends(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"state",
		"cross-suite",
		"repohealer-deb822-audit.jsonl",
	)

	first := Deb822RepairAuditEvent{
		Event:           "apt_deb822_repository_repair",
		OccurredAt:      time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC),
		Status:          Deb822RepairApprovalStatusDeclined,
		FailureCategory: RepairFailureDeclined,
	}
	second := Deb822RepairAuditEvent{
		Event:           "apt_deb822_repository_repair",
		OccurredAt:      time.Date(2026, time.September, 12, 0, 1, 0, 0, time.UTC),
		Status:          Deb822RepairApprovalStatusBlocked,
		FailureCategory: RepairFailureBlocked,
	}

	if err := AppendDeb822RepairAuditEvent(path, first); err != nil {
		t.Fatalf("first append error = %v", err)
	}
	if err := AppendDeb822RepairAuditEvent(path, second); err != nil {
		t.Fatalf("second append error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !strings.HasSuffix(string(content), "\n") {
		t.Fatalf("audit log must end with newline: %q", content)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2; content = %q", len(lines), content)
	}

	var gotFirst, gotSecond Deb822RepairAuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &gotFirst); err != nil {
		t.Fatalf("first JSON line error = %v; line = %q", err, lines[0])
	}
	if err := json.Unmarshal([]byte(lines[1]), &gotSecond); err != nil {
		t.Fatalf("second JSON line error = %v; line = %q", err, lines[1])
	}

	if gotFirst.Status != Deb822RepairApprovalStatusDeclined {
		t.Fatalf("first status = %q", gotFirst.Status)
	}
	if gotSecond.Status != Deb822RepairApprovalStatusBlocked {
		t.Fatalf("second status = %q", gotSecond.Status)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("os.Stat() error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("audit file mode = %o, want 600", got)
		}

		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("os.Stat(parent) error = %v", err)
		}
		if got := parent.Mode().Perm(); got != 0o700 {
			t.Fatalf("audit directory mode = %o, want 700", got)
		}
	}
}

func TestAppendDeb822RepairAuditEventRejectsEmptyPath(t *testing.T) {
	err := AppendDeb822RepairAuditEvent("", Deb822RepairAuditEvent{})
	if err == nil {
		t.Fatal("AppendDeb822RepairAuditEvent() error = nil, want error")
	}
}

func TestAppendDeb822RepairAuditEventReturnsErrorForDirectoryPath(t *testing.T) {
	path := t.TempDir()

	err := AppendDeb822RepairAuditEvent(path, Deb822RepairAuditEvent{})
	if err == nil {
		t.Fatal("AppendDeb822RepairAuditEvent() error = nil, want error")
	}
}

func TestDeb822RepairAuditPathUsesEnvironmentOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "repohealer.jsonl")
	t.Setenv(deb822RepairAuditPathEnv, "  "+want+"  ")

	if got := Deb822RepairAuditPath(); got != want {
		t.Fatalf("Deb822RepairAuditPath() = %q, want %q", got, want)
	}
}

func TestDeb822RepairAuditPathUsesDefaultWhenUnset(t *testing.T) {
	t.Setenv(deb822RepairAuditPathEnv, "")

	if got := Deb822RepairAuditPath(); got != defaultDeb822RepairAuditPath {
		t.Fatalf(
			"Deb822RepairAuditPath() = %q, want %q",
			got,
			defaultDeb822RepairAuditPath,
		)
	}
}
