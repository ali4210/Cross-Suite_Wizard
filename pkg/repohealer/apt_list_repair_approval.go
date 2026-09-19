package repohealer

import (
	"fmt"
	"reflect"
	"strings"
)

type HashiCorpAPTListRepairApprovalStatus string

const (
	HashiCorpAPTListRepairApprovalBlocked HashiCorpAPTListRepairApprovalStatus = "blocked"
	HashiCorpAPTListRepairApprovalApplied HashiCorpAPTListRepairApprovalStatus = "applied"
	HashiCorpAPTListRepairApprovalFailed  HashiCorpAPTListRepairApprovalStatus = "failed"
)

type HashiCorpAPTListRepairApprovalResult struct {
	Status      HashiCorpAPTListRepairApprovalStatus
	ActionID    string
	ProfileID   string
	KeyringPath string
	Execution   HashiCorpAPTListRepairExecutionResult
	Reason      string
}

func ApproveAndApplyHashiCorpAPTListRepair(
	exec Executor,
	request HashiCorpAPTListRepairExecutionRequest,
	preflight HashiCorpAPTListRepairPreflight,
) HashiCorpAPTListRepairApprovalResult {
	result := HashiCorpAPTListRepairApprovalResult{
		Status:      HashiCorpAPTListRepairApprovalBlocked,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		KeyringPath: request.KeyringPath,
	}

	if err := validateHashiCorpAPTListRepairApprovalBinding(
		request,
		preflight,
	); err != nil {
		result.Reason = err.Error()
		return result
	}

	if !HashiCorpAPTListRepairExecutionEnabled() {
		result.Reason = "HashiCorp APT-list repair execution is disabled by operator policy; set CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED=true only for approved maintenance"
		return result
	}

	result.Execution = ExecuteHashiCorpAPTListRepair(
		exec,
		request,
		preflight,
	)

	if result.Execution.Status == HashiCorpAPTListRepairExecutionApplied {
		result.Status = HashiCorpAPTListRepairApprovalApplied
		return result
	}

	result.Status = HashiCorpAPTListRepairApprovalFailed
	result.Reason = strings.TrimSpace(result.Execution.Reason)
	if result.Reason == "" {
		result.Reason = "HashiCorp APT-list repair execution did not report success"
	}

	return result
}

func validateHashiCorpAPTListRepairApprovalBinding(
	request HashiCorpAPTListRepairExecutionRequest,
	preflight HashiCorpAPTListRepairPreflight,
) error {
	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair approval blocked: execution request is invalid: %w",
			err,
		)
	}

	if !preflight.Ready {
		return fmt.Errorf(
			"HashiCorp APT-list repair approval blocked: preflight is not ready: %s",
			strings.TrimSpace(preflight.Reason),
		)
	}

	if !reflect.DeepEqual(preflight.Request, request) {
		return fmt.Errorf(
			"HashiCorp APT-list repair approval blocked: preflight does not match the exact execution request",
		)
	}

	return nil
}
