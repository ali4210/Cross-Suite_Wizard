package repohealer

import (
	"os"
	"strings"
	"time"
)

const (
	rpmRepairAuditPathEnv     = "CROSS_SUITE_RPM_AUDIT_PATH"
	defaultRPMRepairAuditPath = "/var/log/cross-suite/repohealer-rpm-audit.jsonl"
)

// RPMRepairAuditPath mirrors RepairAuditPath for the dnf/yum/zypper family.
func RPMRepairAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(rpmRepairAuditPathEnv)); path != "" {
		return path
	}
	return defaultRPMRepairAuditPath
}

// BuildRPMRepairAuditEvent mirrors BuildRepairAuditEvent (audit.go). It reuses the same
// RepairAuditEvent shape and AppendRepairAuditEvent writer — neither has anything
// APT-specific in it beyond the Event name this function sets and the failure-signature
// substrings classifyRPMRepairFailure checks, both handled here.
func BuildRPMRepairAuditEvent(result ApprovalExecutionResult, occurredAt time.Time) RepairAuditEvent {
	repair := result.RepairResult

	return RepairAuditEvent{
		Event:           "rpm_repository_repair",
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
		FailureCategory: classifyRPMRepairFailure(result),
	}
}

func classifyRPMRepairFailure(result ApprovalExecutionResult) RepairFailureCategory {
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
		strings.Contains(errorText, "makecache"),
		strings.Contains(errorText, "refresh"),
		strings.Contains(errorText, "gpg check failed"),
		strings.Contains(errorText, "nokey"),
		strings.Contains(errorText, "signature verification failed"):
		return RepairFailureVerification
	case result.Decision == ApprovalExecutionExecuted:
		return RepairFailureExecution
	default:
		return RepairFailureUnknown
	}
}
