package repohealer

import (
	"strings"
	"time"
)

type HashiCorpAPTListRepairAuditEvent struct {
	Event           string                               `json:"event"`
	OccurredAt      time.Time                            `json:"occurred_at"`
	Status          HashiCorpAPTListRepairApprovalStatus `json:"status"`
	ActionID        string                               `json:"action_id,omitempty"`
	ProfileID       string                               `json:"profile_id,omitempty"`
	KeyringPath     string                               `json:"keyring_path,omitempty"`
	RepairAttempted bool                                 `json:"repair_attempted"`
	Applied         bool                                 `json:"applied"`
	RolledBack      bool                                 `json:"rolled_back"`
	FailureCategory RepairFailureCategory                `json:"failure_category"`
}

func BuildHashiCorpAPTListRepairAuditEvent(
	result HashiCorpAPTListRepairApprovalResult,
	occurredAt time.Time,
) HashiCorpAPTListRepairAuditEvent {
	execution := result.Execution

	return HashiCorpAPTListRepairAuditEvent{
		Event:           "hashicorp_apt_list_repair",
		OccurredAt:      occurredAt.UTC(),
		Status:          result.Status,
		ActionID:        result.ActionID,
		ProfileID:       firstNonEmpty(result.ProfileID, execution.ProfileID),
		KeyringPath:     firstNonEmpty(result.KeyringPath, execution.KeyringPath),
		RepairAttempted: execution.Attempted,
		Applied:         execution.Applied,
		RolledBack:      execution.RolledBack,
		FailureCategory: classifyHashiCorpAPTListRepairFailure(result),
	}
}

func classifyHashiCorpAPTListRepairFailure(
	result HashiCorpAPTListRepairApprovalResult,
) RepairFailureCategory {
	switch result.Status {
	case HashiCorpAPTListRepairApprovalBlocked:
		return RepairFailureBlocked
	case HashiCorpAPTListRepairApprovalApplied:
		return RepairFailureNone
	}

	reason := strings.ToLower(result.Reason)
	switch {
	case strings.Contains(reason, "fingerprint_mismatch"),
		strings.Contains(reason, "fingerprint mismatch"):
		return RepairFailureFingerprint
	case strings.Contains(reason, "snapshot"):
		return RepairFailureSnapshot
	case strings.Contains(reason, "rollback"):
		return RepairFailureRollback
	case strings.Contains(reason, "verification"),
		strings.Contains(reason, "apt-get update"),
		strings.Contains(reason, "no_pubkey"),
		strings.Contains(reason, "badsig"),
		strings.Contains(reason, "expkeysig"):
		return RepairFailureVerification
	case result.Status == HashiCorpAPTListRepairApprovalFailed:
		return RepairFailureExecution
	default:
		return RepairFailureUnknown
	}
}
