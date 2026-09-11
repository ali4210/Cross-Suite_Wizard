package repohealer

import (
	"fmt"
	"strings"
)

type Deb822RepairApprovalStatus string

const (
	Deb822RepairApprovalStatusBlocked  Deb822RepairApprovalStatus = "blocked"
	Deb822RepairApprovalStatusDeclined Deb822RepairApprovalStatus = "declined"
	Deb822RepairApprovalStatusApplied  Deb822RepairApprovalStatus = "applied"
	Deb822RepairApprovalStatusFailed   Deb822RepairApprovalStatus = "failed"
)

type Deb822RepairApprovalResult struct {
	Status      Deb822RepairApprovalStatus
	ActionID    string
	ProfileID   string
	SourceFile  string
	KeyringPath string
	ApplyResult Deb822RepairApplyResult
	Reason      string
}

func ApproveAndApplyDeb822Repair(
	exec Executor,
	inspection Deb822RepairInspection,
	request Deb822RepairExecutionRequest,
	response string,
) Deb822RepairApprovalResult {
	result := Deb822RepairApprovalResult{
		Status:      Deb822RepairApprovalStatusBlocked,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		SourceFile:  request.SourceFile,
		KeyringPath: request.KeyringPath,
	}

	if err := validateDeb822ApprovalBinding(inspection, request); err != nil {
		result.Reason = err.Error()
		return result
	}

	if !isExplicitDeb822RepairApproval(response) {
		result.Status = Deb822RepairApprovalStatusDeclined
		result.Reason = "Deb822 repair was not approved"
		return result
	}

	result.ApplyResult = ApplyDeb822RepairExecution(exec, request)

	if result.ApplyResult.Applied {
		result.Status = Deb822RepairApprovalStatusApplied
		return result
	}

	result.Status = Deb822RepairApprovalStatusFailed
	if result.ApplyResult.Error != nil {
		result.Reason = result.ApplyResult.Error.Error()
	} else {
		result.Reason = "Deb822 repair execution did not report success"
	}

	return result
}

func validateDeb822ApprovalBinding(
	inspection Deb822RepairInspection,
	request Deb822RepairExecutionRequest,
) error {
	if !inspection.Ready {
		return fmt.Errorf(
			"Deb822 repair approval blocked: inspection is not ready: %s",
			strings.TrimSpace(inspection.BlockReason),
		)
	}

	if err := ValidateDeb822RepairExecutionRequest(request); err != nil {
		return fmt.Errorf(
			"Deb822 repair approval blocked: execution request is invalid: %w",
			err,
		)
	}

	if inspection.ActionID != request.ActionID ||
		inspection.ProfileID != request.ProfileID ||
		inspection.SourceFile != request.SourceFile ||
		inspection.KeyringPath != request.KeyringPath ||
		inspection.RenderedSource != request.RenderedSource ||
		!sameOrderedStrings(
			inspection.SnapshotTargets,
			request.SnapshotTargets,
		) {
		return fmt.Errorf(
			"Deb822 repair approval blocked: inspection does not match the exact execution request",
		)
	}

	return nil
}

func isExplicitDeb822RepairApproval(response string) bool {
	switch strings.ToLower(strings.TrimSpace(response)) {
	case "yes", "y":
		return true
	default:
		return false
	}
}
