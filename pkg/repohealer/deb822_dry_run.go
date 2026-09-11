package repohealer

import (
	"strings"
	"time"
)

type Deb822RepairPreviewAuditEvent struct {
	Event           string                `json:"event"`
	OccurredAt      time.Time             `json:"occurred_at"`
	Ready           bool                  `json:"ready"`
	ActionID        string                `json:"action_id,omitempty"`
	ProfileID       string                `json:"profile_id,omitempty"`
	SourceFile      string                `json:"source_file,omitempty"`
	KeyringPath     string                `json:"keyring_path,omitempty"`
	FailureCategory RepairFailureCategory `json:"failure_category,omitempty"`
}

func BuildDeb822RepairPreviewAuditEvent(
	preview Deb822RepairDryRunResult,
	occurredAt time.Time,
) Deb822RepairPreviewAuditEvent {
	event := Deb822RepairPreviewAuditEvent{
		Event:       "apt_deb822_repository_repair_preview",
		OccurredAt:  occurredAt.UTC(),
		Ready:       preview.Ready,
		ActionID:    preview.ActionID,
		ProfileID:   preview.ProfileID,
		SourceFile:  preview.SourceFile,
		KeyringPath: preview.KeyringPath,
	}

	if !preview.Ready {
		event.FailureCategory = RepairFailureBlocked
	}

	return event
}

type Deb822RepairDryRunResult struct {
	Ready                bool
	Reason               string
	ActionID             string
	FindingCode          string
	ProfileID            string
	ProfileDisplayName   string
	RepositoryURL        string
	SourceFile           string
	KeyringPath          string
	RenderedSource       string
	SnapshotTargets      []string
	ExpectedFingerprints []string
}

func PreviewDeb822Repair(
	inspection Deb822RepairInspection,
	request Deb822RepairExecutionRequest,
) Deb822RepairDryRunResult {
	result := Deb822RepairDryRunResult{
		ActionID:             request.ActionID,
		FindingCode:          request.FindingCode,
		ProfileID:            request.ProfileID,
		ProfileDisplayName:   request.ProfileDisplayName,
		RepositoryURL:        request.RepositoryURL,
		SourceFile:           request.SourceFile,
		KeyringPath:          request.KeyringPath,
		RenderedSource:       request.RenderedSource,
		SnapshotTargets:      append([]string(nil), request.SnapshotTargets...),
		ExpectedFingerprints: append([]string(nil), request.ExpectedFingerprints...),
	}

	if err := validateDeb822ApprovalBinding(inspection, request); err != nil {
		result.Reason = strings.TrimSpace(err.Error())
		return result
	}

	result.Ready = true
	return result
}
