package repohealer

import (
	"fmt"
	"strings"
)

type HashiCorpAPTListRepairApprovalStatus string

const (
	HashiCorpAPTListRepairApprovalStatusBlocked  HashiCorpAPTListRepairApprovalStatus = "blocked"
	HashiCorpAPTListRepairApprovalStatusDeclined HashiCorpAPTListRepairApprovalStatus = "declined"
	HashiCorpAPTListRepairApprovalStatusApplied  HashiCorpAPTListRepairApprovalStatus = "applied"
	HashiCorpAPTListRepairApprovalStatusFailed   HashiCorpAPTListRepairApprovalStatus = "failed"
)

type HashiCorpAPTListRepairApprovalResult struct {
	Status      HashiCorpAPTListRepairApprovalStatus
	ActionID    string
	ProfileID   string
	SourceFile  string
	KeyringPath string
	ApplyResult HashiCorpAPTListRepairApplyResult
	Reason      string
}

// ApproveAndApplyHashiCorpAPTListRepair is the single gated entry point for actually applying
// the HashiCorp APT-list keyring repair. In order it requires: a ready preflight bound to the
// exact approved request, an explicit typed "yes" response, the operator-policy env flag, and
// a clear safety gate (disk space / clock skew / dpkg health) — any one of these failing blocks
// the repair with no system change.
func ApproveAndApplyHashiCorpAPTListRepair(
	exec Executor,
	preflight HashiCorpAPTListRepairPreflight,
	response string,
) HashiCorpAPTListRepairApprovalResult {
	request := preflight.Request
	result := HashiCorpAPTListRepairApprovalResult{
		Status:      HashiCorpAPTListRepairApprovalStatusBlocked,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		SourceFile:  request.SourceFile,
		KeyringPath: request.KeyringPath,
	}

	if !preflight.Ready {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair approval blocked: preflight is not ready: %s",
			strings.TrimSpace(preflight.Reason),
		)
		return result
	}

	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair approval blocked: execution request is invalid: %s",
			err.Error(),
		)
		return result
	}

	if !isExplicitHashiCorpAPTListRepairApproval(response) {
		result.Status = HashiCorpAPTListRepairApprovalStatusDeclined
		result.Reason = "HashiCorp APT-list repair was not approved"
		return result
	}

	if !HashiCorpAPTListRepairExecutionEnabled() {
		result.Reason = "HashiCorp APT-list repair execution is disabled by operator policy; " +
			"set CROSS_SUITE_APTLIST_REPAIR_ENABLED=true only for approved maintenance"
		return result
	}

	safety := EvaluateHashiCorpAPTListRepairSafety(exec)
	if blocked, reason := safety.Blocked(); blocked {
		result.Reason = reason
		return result
	}

	result.ApplyResult = ApplyHashiCorpAPTListRepair(exec, preflight)

	if result.ApplyResult.Applied {
		result.Status = HashiCorpAPTListRepairApprovalStatusApplied
		return result
	}

	result.Status = HashiCorpAPTListRepairApprovalStatusFailed
	if result.ApplyResult.Error != nil {
		result.Reason = result.ApplyResult.Error.Error()
	} else {
		result.Reason = "HashiCorp APT-list repair execution did not report success"
	}

	return result
}

func isExplicitHashiCorpAPTListRepairApproval(response string) bool {
	switch strings.ToLower(strings.TrimSpace(response)) {
	case "yes", "y":
		return true
	default:
		return false
	}
}
