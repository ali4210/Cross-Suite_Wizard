package repohealer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBuildRepairAuditEventForAppliedRepair(t *testing.T) {
	occurredAt := time.Date(2026, time.September, 5, 2, 0, 0, 0, time.FixedZone("+06", 6*60*60))

	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:            "apt-keyring-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_KEYRING_PATH_MISSING",
		},
		RepairResult: RepairResult{
			Attempted: true,
			Applied:   true,
			ProfileID: "docker-ce",
			Snapshot: Snapshot{
				ID:      "apt-test",
				Path:    "/var/lib/cross-suite/snapshots/apt-test",
				Created: true,
			},
		},
	}, occurredAt)

	if event.Event != "apt_repository_repair" {
		t.Fatalf("event = %q", event.Event)
	}
	if event.Decision != ApprovalExecutionExecuted {
		t.Fatalf("decision = %q", event.Decision)
	}
	if event.FailureCategory != RepairFailureNone {
		t.Fatalf("failure category = %q, want %q", event.FailureCategory, RepairFailureNone)
	}
	if !event.RepairAttempted || !event.Applied || event.RolledBack {
		t.Fatalf("unexpected applied state: %#v", event)
	}
	if event.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q", event.ProfileID)
	}
	if event.SnapshotPath != "/var/lib/cross-suite/snapshots/apt-test" {
		t.Fatalf("snapshot path = %q", event.SnapshotPath)
	}
	if !event.OccurredAt.Equal(occurredAt.UTC()) {
		t.Fatalf("occurred at = %s, want %s", event.OccurredAt, occurredAt.UTC())
	}
}

func TestBuildRepairAuditEventForDeclinedRepair(t *testing.T) {
	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionDeclined,
		Action: RepairAction{
			ID:            "apt-keyring-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_KEYRING_PATH_MISSING",
		},
		Error: errors.New("repair action was not explicitly approved"),
	}, time.Now())

	if event.FailureCategory != RepairFailureDeclined {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
	if event.RepairAttempted || event.Applied || event.RolledBack {
		t.Fatalf("declined event must record no repair activity: %#v", event)
	}
}

func TestBuildRepairAuditEventForBlockedRepair(t *testing.T) {
	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionBlocked,
		Action: RepairAction{
			ID:            "apt-source-binding-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_SOURCE_KEYRING_MISMATCH",
		},
		Error: errors.New("repair action is blocked"),
	}, time.Now())

	if event.FailureCategory != RepairFailureBlocked {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
	if event.RepairAttempted || event.Applied || event.RolledBack {
		t.Fatalf("blocked event must record no repair activity: %#v", event)
	}
}

func TestBuildRepairAuditEventClassifiesFingerprintMismatch(t *testing.T) {
	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:            "apt-keyring-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_KEYRING_PATH_MISSING",
		},
		RepairResult: RepairResult{
			Attempted:  true,
			RolledBack: true,
			ProfileID:  "docker-ce",
			Output:     "REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce",
		},
		Error: errors.New("keyring/source repair failed: fingerprint_mismatch"),
	}, time.Now())

	if event.FailureCategory != RepairFailureFingerprint {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
	if !event.RepairAttempted || event.Applied || !event.RolledBack {
		t.Fatalf("unexpected fingerprint failure state: %#v", event)
	}
}

func TestBuildRepairAuditEventClassifiesVerificationFailure(t *testing.T) {
	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:            "apt-keyring-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_KEYRING_PATH_MISSING",
		},
		RepairResult: RepairResult{
			Attempted:       true,
			RolledBack:      true,
			ProfileID:       "docker-ce",
			VerificationOut: "NO_PUBKEY EB3E94ADBE1229CF",
		},
		Error: errors.New("post-repair APT verification failed: exit status 100"),
	}, time.Now())

	if event.FailureCategory != RepairFailureVerification {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
}

func TestRepairAuditEventJSONDoesNotContainRawRepairOutput(t *testing.T) {
	event := BuildRepairAuditEvent(ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action: RepairAction{
			ID:            "apt-keyring-repair-docker-ce",
			ProfileID:     "docker-ce",
			RepositoryURL: "https://download.docker.com/linux/debian",
			FindingCode:   "APT_KEYRING_PATH_MISSING",
		},
		RepairResult: RepairResult{
			Attempted:       true,
			Output:          "SECRET_REPAIR_OUTPUT_DO_NOT_LOG",
			VerificationOut: "SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
		},
		Error: errors.New("SECRET_ERROR_DO_NOT_LOG"),
	}, time.Now())

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	text := string(encoded)
	for _, forbidden := range []string{
		"SECRET_REPAIR_OUTPUT_DO_NOT_LOG",
		"SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
		"SECRET_ERROR_DO_NOT_LOG",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("audit JSON must not contain %q: %s", forbidden, text)
		}
	}
}
