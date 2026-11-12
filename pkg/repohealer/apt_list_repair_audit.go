package repohealer

import (
	"os"
	"strings"
	"time"
)

const (
	hashicorpAPTListRepairAuditPathEnv     = "CROSS_SUITE_APTLIST_AUDIT_PATH"
	defaultHashiCorpAPTListRepairAuditPath = "/var/log/cross-suite/repohealer-aptlist-audit.jsonl"
)

type HashiCorpAPTListRepairAuditEvent struct {
	Event           string                               `json:"event"`
	OccurredAt      time.Time                            `json:"occurred_at"`
	Status          HashiCorpAPTListRepairApprovalStatus `json:"status"`
	ActionID        string                               `json:"action_id,omitempty"`
	ProfileID       string                               `json:"profile_id,omitempty"`
	SourceFile      string                               `json:"source_file,omitempty"`
	KeyringPath     string                               `json:"keyring_path,omitempty"`
	RepairAttempted bool                                 `json:"repair_attempted"`
	Applied         bool                                 `json:"applied"`
	RolledBack      bool                                 `json:"rolled_back"`
	SnapshotID      string                               `json:"snapshot_id,omitempty"`
	SnapshotPath    string                               `json:"snapshot_path,omitempty"`
	FailureCategory RepairFailureCategory                `json:"failure_category"`
}

func HashiCorpAPTListRepairAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(hashicorpAPTListRepairAuditPathEnv)); path != "" {
		return path
	}

	return defaultHashiCorpAPTListRepairAuditPath
}

func BuildHashiCorpAPTListRepairAuditEvent(
	result HashiCorpAPTListRepairApprovalResult,
	occurredAt time.Time,
) HashiCorpAPTListRepairAuditEvent {
	repair := result.ApplyResult

	return HashiCorpAPTListRepairAuditEvent{
		Event:           "apt_list_hashicorp_repository_repair",
		OccurredAt:      occurredAt.UTC(),
		Status:          result.Status,
		ActionID:        result.ActionID,
		ProfileID:       firstNonEmpty(result.ProfileID, repair.ProfileID),
		SourceFile:      firstNonEmpty(result.SourceFile, repair.SourceFile),
		KeyringPath:     firstNonEmpty(result.KeyringPath, repair.KeyringPath),
		RepairAttempted: repair.Attempted,
		Applied:         repair.Applied,
		RolledBack:      repair.RolledBack,
		SnapshotID:      repair.Snapshot.ID,
		SnapshotPath:    repair.Snapshot.Path,
		FailureCategory: classifyHashiCorpAPTListRepairFailure(result),
	}
}

func AppendHashiCorpAPTListRepairAuditEvent(
	path string,
	event HashiCorpAPTListRepairAuditEvent,
) error {
	return appendDeb822RepairAuditJSONL(path, event)
}

func classifyHashiCorpAPTListRepairFailure(
	result HashiCorpAPTListRepairApprovalResult,
) RepairFailureCategory {
	switch result.Status {
	case HashiCorpAPTListRepairApprovalStatusBlocked:
		return RepairFailureBlocked
	case HashiCorpAPTListRepairApprovalStatusDeclined:
		return RepairFailureDeclined
	case HashiCorpAPTListRepairApprovalStatusApplied:
		return RepairFailureNone
	}

	errorText := strings.ToLower(result.Reason)
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
	case result.Status == HashiCorpAPTListRepairApprovalStatusFailed:
		return RepairFailureExecution
	default:
		return RepairFailureUnknown
	}
}
