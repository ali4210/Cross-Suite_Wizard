package repohealer

import (
	"strings"
	"time"
)

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
