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
	deb822RepairAuditPathEnv     = "CROSS_SUITE_DEB822_AUDIT_PATH"
	defaultDeb822RepairAuditPath = "/var/log/cross-suite/repohealer-deb822-audit.jsonl"
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

func Deb822RepairAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(deb822RepairAuditPathEnv)); path != "" {
		return path
	}

	return defaultDeb822RepairAuditPath
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

func AppendDeb822RepairAuditEvent(
	path string,
	event Deb822RepairAuditEvent,
) error {
	return appendDeb822RepairAuditJSONL(path, event)
}

func AppendDeb822RepairPreviewAuditEvent(
	path string,
	event Deb822RepairPreviewAuditEvent,
) error {
	return appendDeb822RepairAuditJSONL(path, event)
}

func appendDeb822RepairAuditJSONL(path string, event any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("Deb822 audit path is empty")
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create Deb822 audit directory %q: %w", parent, err)
	}

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open Deb822 audit file %q: %w", path, err)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode Deb822 audit event: %w", err)
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("append Deb822 audit event to %q: %w", path, err)
	}

	return nil
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
