package repohealer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildHashiCorpAPTListRepairAuditEventForAppliedRepair(
	t *testing.T,
) {
	occurredAt := time.Date(2026, time.September, 20, 0, 0, 0, 0, time.UTC)

	event := BuildHashiCorpAPTListRepairAuditEvent(
		HashiCorpAPTListRepairApprovalResult{
			Status:      HashiCorpAPTListRepairApprovalApplied,
			ActionID:    "apt-list-repair-hashicorp",
			ProfileID:   HashiCorpAPTListProfileID,
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			Execution: HashiCorpAPTListRepairExecutionResult{
				Attempted: true,
				Applied:   true,
			},
		},
		occurredAt,
	)

	if event.Event != "hashicorp_apt_list_repair" {
		t.Fatalf("event = %q, want hashicorp_apt_list_repair", event.Event)
	}
	if !event.OccurredAt.Equal(occurredAt) {
		t.Fatalf("occurred at = %s, want %s", event.OccurredAt, occurredAt)
	}
	if event.Status != HashiCorpAPTListRepairApprovalApplied {
		t.Fatalf("status = %q, want applied", event.Status)
	}
	if !event.RepairAttempted || !event.Applied || event.RolledBack {
		t.Fatalf("unexpected repair flags: %#v", event)
	}
	if event.FailureCategory != RepairFailureNone {
		t.Fatalf(
			"failure category = %q, want %q",
			event.FailureCategory,
			RepairFailureNone,
		)
	}
}

func TestBuildHashiCorpAPTListRepairAuditEventClassifiesFailureAndExcludesRawOutput(
	t *testing.T,
) {
	event := BuildHashiCorpAPTListRepairAuditEvent(
		HashiCorpAPTListRepairApprovalResult{
			Status:      HashiCorpAPTListRepairApprovalFailed,
			ActionID:    "apt-list-repair-hashicorp",
			ProfileID:   HashiCorpAPTListProfileID,
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			Execution: HashiCorpAPTListRepairExecutionResult{
				Attempted:       true,
				RolledBack:      true,
				Output:          "RAW_MUTATION_OUTPUT_MUST_NOT_APPEAR",
				VerificationOut: "RAW_VERIFICATION_OUTPUT_MUST_NOT_APPEAR",
			},
			Reason: "HashiCorp APT-list repair verification failed: NO_PUBKEY",
		},
		time.Now(),
	)

	if event.FailureCategory != RepairFailureVerification {
		t.Fatalf(
			"failure category = %q, want %q",
			event.FailureCategory,
			RepairFailureVerification,
		)
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for _, forbidden := range []string{
		"RAW_MUTATION_OUTPUT_MUST_NOT_APPEAR",
		"RAW_VERIFICATION_OUTPUT_MUST_NOT_APPEAR",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit JSON must not contain %q: %s", forbidden, encoded)
		}
	}
}

func TestBuildHashiCorpAPTListRepairAuditEventClassifiesBlockedDecision(
	t *testing.T,
) {
	event := BuildHashiCorpAPTListRepairAuditEvent(
		HashiCorpAPTListRepairApprovalResult{
			Status:   HashiCorpAPTListRepairApprovalBlocked,
			ActionID: "apt-list-repair-hashicorp",
			Reason:   "operator policy is disabled",
		},
		time.Now(),
	)

	if event.FailureCategory != RepairFailureBlocked {
		t.Fatalf(
			"failure category = %q, want %q",
			event.FailureCategory,
			RepairFailureBlocked,
		)
	}
	if event.RepairAttempted || event.Applied || event.RolledBack {
		t.Fatalf("blocked event has repair flags: %#v", event)
	}
}
