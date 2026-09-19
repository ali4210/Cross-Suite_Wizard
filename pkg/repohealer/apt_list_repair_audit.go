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

const (
	hashicorpAPTListRepairAuditPathEnv     = "CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_AUDIT_PATH"
	defaultHashiCorpAPTListRepairAuditPath = "/var/log/cross-suite/repohealer-hashicorp-apt-list-audit.jsonl"
)

func HashiCorpAPTListRepairAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(hashicorpAPTListRepairAuditPathEnv)); path != "" {
		return path
	}

	return defaultHashiCorpAPTListRepairAuditPath
}

func AppendHashiCorpAPTListRepairAuditEvent(
	path string,
	event HashiCorpAPTListRepairAuditEvent,
) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("HashiCorp APT-list repair audit path is empty")
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf(
			"create HashiCorp APT-list repair audit directory %q: %w",
			parent,
			err,
		)
	}

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0o600,
	)
	if err != nil {
		return fmt.Errorf(
			"open HashiCorp APT-list repair audit file %q: %w",
			path,
			err,
		)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf(
			"encode HashiCorp APT-list repair audit event: %w",
			err,
		)
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf(
			"append HashiCorp APT-list repair audit event to %q: %w",
			path,
			err,
		)
	}

	return nil
}
