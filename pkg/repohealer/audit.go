package repohealer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	repairAuditPathEnv     = "CROSS_SUITE_APT_AUDIT_PATH"
	defaultRepairAuditPath = "/var/log/cross-suite/repohealer-apt-audit.jsonl"
)

// RepairAuditPath returns the local path the plain (non-Deb822) APT repair audit trail is
// appended to, mirroring Deb822RepairAuditPath's env-override convention.
func RepairAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(repairAuditPathEnv)); path != "" {
		return path
	}

	return defaultRepairAuditPath
}

// AppendRepairAuditEvent persists a plain APT repair audit event as a JSON line, the same
// way AppendDeb822RepairAuditEvent does for the Deb822 path.
func AppendRepairAuditEvent(path string, event RepairAuditEvent) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("APT repair audit path is empty")
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create APT repair audit directory %q: %w", parent, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open APT repair audit file %q: %w", path, err)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode APT repair audit event: %w", err)
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("append APT repair audit event to %q: %w", path, err)
	}

	return nil
}

type RepairFailureCategory string

const (
	RepairFailureNone           RepairFailureCategory = "none"
	RepairFailureActionNotFound RepairFailureCategory = "action_not_found"
	RepairFailureBlocked        RepairFailureCategory = "blocked"
	RepairFailureDeclined       RepairFailureCategory = "declined"
	RepairFailureSnapshot       RepairFailureCategory = "snapshot_failed"
	RepairFailureFingerprint    RepairFailureCategory = "fingerprint_mismatch"
	RepairFailureVerification   RepairFailureCategory = "verification_failed"
	RepairFailureRollback       RepairFailureCategory = "rollback_failed"
	RepairFailureExecution      RepairFailureCategory = "repair_failed"
	RepairFailureUnknown        RepairFailureCategory = "unknown"
)

type RepairAuditEvent struct {
	Event           string                    `json:"event"`
	OccurredAt      time.Time                 `json:"occurred_at"`
	Decision        ApprovalExecutionDecision `json:"decision"`
	ActionID        string                    `json:"action_id,omitempty"`
	ProfileID       string                    `json:"profile_id,omitempty"`
	RepositoryURL   string                    `json:"repository_url,omitempty"`
	FindingCode     string                    `json:"finding_code,omitempty"`
	RepairAttempted bool                      `json:"repair_attempted"`
	Applied         bool                      `json:"applied"`
	RolledBack      bool                      `json:"rolled_back"`
	SnapshotID      string                    `json:"snapshot_id,omitempty"`
	SnapshotPath    string                    `json:"snapshot_path,omitempty"`
	FailureCategory RepairFailureCategory     `json:"failure_category"`
}

func BuildRepairAuditEvent(result ApprovalExecutionResult, occurredAt time.Time) RepairAuditEvent {
	repair := result.RepairResult

	return RepairAuditEvent{
		Event:           "apt_repository_repair",
		OccurredAt:      occurredAt.UTC(),
		Decision:        result.Decision,
		ActionID:        result.Action.ID,
		ProfileID:       firstNonEmpty(result.Action.ProfileID, repair.ProfileID),
		RepositoryURL:   result.Action.RepositoryURL,
		FindingCode:     result.Action.FindingCode,
		RepairAttempted: repair.Attempted,
		Applied:         repair.Applied,
		RolledBack:      repair.RolledBack,
		SnapshotID:      repair.Snapshot.ID,
		SnapshotPath:    repair.Snapshot.Path,
		FailureCategory: classifyRepairFailure(result),
	}
}

func classifyRepairFailure(result ApprovalExecutionResult) RepairFailureCategory {
	switch result.Decision {
	case ApprovalExecutionActionNotFound:
		return RepairFailureActionNotFound
	case ApprovalExecutionBlocked:
		return RepairFailureBlocked
	case ApprovalExecutionDeclined:
		return RepairFailureDeclined
	case ApprovalExecutionExecuted:
		if result.RepairResult.Applied {
			return RepairFailureNone
		}
	}

	errorText := strings.ToLower(errorText(result))

	switch {
	case strings.Contains(errorText, "fingerprint_mismatch"),
		strings.Contains(errorText, "fingerprint mismatch"):
		return RepairFailureFingerprint
	case strings.Contains(errorText, "snapshot"):
		return RepairFailureSnapshot
	case strings.Contains(errorText, "rollback"):
		return RepairFailureRollback
	case strings.Contains(errorText, "verification"),
		strings.Contains(errorText, "apt-get update"),
		strings.Contains(errorText, "no_pubkey"),
		strings.Contains(errorText, "badsig"),
		strings.Contains(errorText, "expkeysig"):
		return RepairFailureVerification
	case result.Decision == ApprovalExecutionExecuted:
		return RepairFailureExecution
	default:
		return RepairFailureUnknown
	}
}

func errorText(result ApprovalExecutionResult) string {
	if result.Error != nil {
		return result.Error.Error()
	}
	if result.RepairResult.Error != nil {
		return result.RepairResult.Error.Error()
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
