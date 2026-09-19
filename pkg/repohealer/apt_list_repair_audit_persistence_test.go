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

func TestHashiCorpAPTListRepairAuditPathUsesEnvironmentOverride(
	t *testing.T,
) {
	override := filepath.Join(t.TempDir(), "custom", "audit.jsonl")
	t.Setenv("CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_AUDIT_PATH", override)

	if got := HashiCorpAPTListRepairAuditPath(); got != override {
		t.Fatalf("audit path = %q, want %q", got, override)
	}
}

func TestAppendHashiCorpAPTListRepairAuditEventWritesRestrictedJSONL(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	event := HashiCorpAPTListRepairAuditEvent{
		Event:           "hashicorp_apt_list_repair",
		OccurredAt:      time.Date(2026, time.September, 20, 0, 0, 0, 0, time.UTC),
		Status:          HashiCorpAPTListRepairApprovalFailed,
		ActionID:        "apt-list-repair-hashicorp",
		ProfileID:       HashiCorpAPTListProfileID,
		KeyringPath:     "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
		RepairAttempted: true,
		RolledBack:      true,
		FailureCategory: RepairFailureVerification,
	}

	if err := AppendHashiCorpAPTListRepairAuditEvent(path, event); err != nil {
		t.Fatalf("AppendHashiCorpAPTListRepairAuditEvent() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.HasSuffix(content, []byte("\n")) {
		t.Fatalf("audit content must end with newline: %q", content)
	}

	var got HashiCorpAPTListRepairAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(content), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got != event {
		t.Fatalf("audit event = %#v, want %#v", got, event)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestAppendHashiCorpAPTListRepairAuditEventRejectsEmptyPath(
	t *testing.T,
) {
	err := AppendHashiCorpAPTListRepairAuditEvent(
		" \t\n ",
		HashiCorpAPTListRepairAuditEvent{},
	)
	if err == nil {
		t.Fatal("AppendHashiCorpAPTListRepairAuditEvent() unexpectedly succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "path") {
		t.Fatalf("error = %q, want path failure", err)
	}
}

func TestAppendHashiCorpAPTListRepairAuditEventAppendsJSONLLines(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := HashiCorpAPTListRepairAuditEvent{
		Event:      "hashicorp_apt_list_repair",
		OccurredAt: time.Date(2026, time.September, 20, 1, 0, 0, 0, time.UTC),
		Status:     HashiCorpAPTListRepairApprovalBlocked,
	}
	second := HashiCorpAPTListRepairAuditEvent{
		Event:      "hashicorp_apt_list_repair",
		OccurredAt: time.Date(2026, time.September, 20, 2, 0, 0, 0, time.UTC),
		Status:     HashiCorpAPTListRepairApprovalApplied,
	}

	for _, event := range []HashiCorpAPTListRepairAuditEvent{first, second} {
		if err := AppendHashiCorpAPTListRepairAuditEvent(path, event); err != nil {
			t.Fatalf("AppendHashiCorpAPTListRepairAuditEvent() error = %v", err)
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("JSONL lines = %d, want 2: %q", len(lines), content)
	}

	var gotFirst, gotSecond HashiCorpAPTListRepairAuditEvent
	if err := json.Unmarshal(lines[0], &gotFirst); err != nil {
		t.Fatalf("first json.Unmarshal() error = %v", err)
	}
	if err := json.Unmarshal(lines[1], &gotSecond); err != nil {
		t.Fatalf("second json.Unmarshal() error = %v", err)
	}

	if gotFirst != first {
		t.Fatalf("first event = %#v, want %#v", gotFirst, first)
	}
	if gotSecond != second {
		t.Fatalf("second event = %#v, want %#v", gotSecond, second)
	}
}
