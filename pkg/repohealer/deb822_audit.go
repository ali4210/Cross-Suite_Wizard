package repohealer

import (
	"strings"
	"time"
)

type Deb822RepairAuditEvent struct {
	Event           string                     `json:"event"`
	OccurredAt      time.Time                  `json:"occurred_at"`
	Status          Deb822RepairApprovalStatus `json:"status"`
	ActionID        string                     `json:"action_id,omitempty"`
	ProfileID       string                     `json:"profile_id,omitempty"`
	SourceFile      string                     `json:"source_file,omitempty"`
	KeyringPath     string                     `json:"keyring_path,omitempty"`
	RepairAttempted bool                       `json:"repair_attempted"`
	Applied         bool                       `json:"applied"`
	RolledBack      bool                       `json:"rolled_back"`
	SnapshotID      string                     `json:"snapshot_id,omitempty"`
	SnapshotPath    string                     `json:"snapshot_path,omitempty"`
	FailureCategory RepairFailureCategory      `json:"failure_category"`
}

func BuildDeb822RepairAuditEvent(
	result Deb822RepairApprovalResult,
	occurredAt time.Time,
) Deb822RepairAuditEvent {
	repair := result.ApplyResult

	return Deb822RepairAuditEvent{
		Event:           "apt_deb822_repository_repair",
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
		FailureCategory: classifyDeb822RepairFailure(result),
	}
}

func classifyDeb822RepairFailure(
	result Deb822RepairApprovalResult,
) RepairFailureCategory {
	switch result.Status {
	case Deb822RepairApprovalStatusBlocked:
		return RepairFailureBlocked
	case Deb822RepairApprovalStatusDeclined:
		return RepairFailureDeclined
	case Deb822RepairApprovalStatusApplied:
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
	case result.Status == Deb822RepairApprovalStatusFailed:
		return RepairFailureExecution
	default:
		return RepairFailureUnknown
	}
}
