package repohealer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashiCorpAPTListRepairAuditPathDefaultsAndHonorsEnv(t *testing.T) {
	t.Setenv(hashicorpAPTListRepairAuditPathEnv, "")
	if got := HashiCorpAPTListRepairAuditPath(); got != defaultHashiCorpAPTListRepairAuditPath {
		t.Fatalf("path = %q, want default %q", got, defaultHashiCorpAPTListRepairAuditPath)
	}

	t.Setenv(hashicorpAPTListRepairAuditPathEnv, "/tmp/custom-aptlist-audit.jsonl")
	if got := HashiCorpAPTListRepairAuditPath(); got != "/tmp/custom-aptlist-audit.jsonl" {
		t.Fatalf("path = %q, want overridden path", got)
	}
}

func TestBuildHashiCorpAPTListRepairAuditEventAndAppend(t *testing.T) {
	result := HashiCorpAPTListRepairApprovalResult{
		Status:      HashiCorpAPTListRepairApprovalStatusApplied,
		ActionID:    "apt-keyring-repair-hashicorp",
		ProfileID:   HashiCorpAPTListProfileID,
		SourceFile:  "/etc/apt/sources.list.d/hashicorp.list",
		KeyringPath: HashiCorpAPTListKeyringPath,
		ApplyResult: HashiCorpAPTListRepairApplyResult{
			Attempted: true,
			Applied:   true,
			Snapshot: Snapshot{
				ID:      "apt-20260101T000000Z-abc123",
				Path:    "/var/lib/cross-suite/snapshots/apt-20260101T000000Z-abc123",
				Created: true,
			},
		},
	}

	audit := BuildHashiCorpAPTListRepairAuditEvent(result, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	if audit.Event != "apt_list_hashicorp_repository_repair" {
		t.Fatalf("event = %q", audit.Event)
	}
	if audit.FailureCategory != RepairFailureNone {
		t.Fatalf("failure category = %q, want none", audit.FailureCategory)
	}
	if !audit.Applied {
		t.Fatal("expected Applied=true")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "aptlist-audit.jsonl")

	if err := AppendHashiCorpAPTListRepairAuditEvent(path, audit); err != nil {
		t.Fatalf("AppendHashiCorpAPTListRepairAuditEvent() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(raw), "apt_list_hashicorp_repository_repair") {
		t.Fatalf("audit file missing expected event, got: %s", raw)
	}
}

func TestClassifyHashiCorpAPTListRepairFailureCategories(t *testing.T) {
	tests := []struct {
		name   string
		result HashiCorpAPTListRepairApprovalResult
		want   RepairFailureCategory
	}{
		{
			name:   "Blocked",
			result: HashiCorpAPTListRepairApprovalResult{Status: HashiCorpAPTListRepairApprovalStatusBlocked},
			want:   RepairFailureBlocked,
		},
		{
			name:   "Declined",
			result: HashiCorpAPTListRepairApprovalResult{Status: HashiCorpAPTListRepairApprovalStatusDeclined},
			want:   RepairFailureDeclined,
		},
		{
			name: "Failed with verification reason",
			result: HashiCorpAPTListRepairApprovalResult{
				Status: HashiCorpAPTListRepairApprovalStatusFailed,
				Reason: "post-repair HashiCorp APT-list verification failed: repository trust or fetch errors were reported",
			},
			want: RepairFailureVerification,
		},
		{
			name: "Failed with no specific reason",
			result: HashiCorpAPTListRepairApprovalResult{
				Status: HashiCorpAPTListRepairApprovalStatusFailed,
				Reason: "something unexpected happened",
			},
			want: RepairFailureExecution,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyHashiCorpAPTListRepairFailure(test.result)
			if got != test.want {
				t.Fatalf("classifyHashiCorpAPTListRepairFailure() = %q, want %q", got, test.want)
			}
		})
	}
}
