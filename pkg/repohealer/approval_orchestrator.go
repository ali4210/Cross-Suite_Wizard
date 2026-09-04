package repohealer

import "fmt"

type ApprovalExecutionDecision string

const (
	ApprovalExecutionActionNotFound ApprovalExecutionDecision = "action_not_found"
	ApprovalExecutionBlocked        ApprovalExecutionDecision = "blocked"
	ApprovalExecutionDeclined       ApprovalExecutionDecision = "declined"
	ApprovalExecutionExecuted       ApprovalExecutionDecision = "executed"
)

type ApprovalExecutionResult struct {
	Decision     ApprovalExecutionDecision
	Action       RepairAction
	RepairResult RepairResult
	Error        error
}

func ApproveAndApplyAPTRepair(
	exec Executor,
	result Result,
	actionID string,
	response string,
) ApprovalExecutionResult {
	actions := BuildRepairPlan(result)

	var selected RepairAction
	found := false
	for _, action := range actions {
		if action.ID == actionID {
			selected = action
			found = true
			break
		}
	}

	if !found {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Error:    fmt.Errorf("repair action %q was not found in the current plan", actionID),
		}
	}

	if !selected.Eligible {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionBlocked,
			Action:   selected,
			Error: fmt.Errorf(
				"repair action %q is blocked: %s",
				selected.ID,
				selected.BlockReason,
			),
		}
	}

	if !IsRepairApproved(selected, response) {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionDeclined,
			Action:   selected,
			Error: fmt.Errorf(
				"repair action %q was not explicitly approved",
				selected.ID,
			),
		}
	}

	profile, ok := FindVendorProfile(ManagerAPT, selected.RepositoryURL)
	if !ok || profile.ID != selected.ProfileID {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Action:   selected,
			Error: fmt.Errorf(
				"repair action %q does not resolve to its approved APT vendor profile",
				selected.ID,
			),
		}
	}

	findingMatched := false
	for _, finding := range result.Findings {
		if finding.Code == selected.FindingCode &&
			finding.RepositoryURL == selected.RepositoryURL {
			findingMatched = true
			break
		}
	}

	if !findingMatched {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Action:   selected,
			Error: fmt.Errorf(
				"repair action %q no longer matches the diagnosis findings",
				selected.ID,
			),
		}
	}

	repairResult := applyKnownAPTProfileRepair(exec, result.Target, profile)

	return ApprovalExecutionResult{
		Decision:     ApprovalExecutionExecuted,
		Action:       selected,
		RepairResult: repairResult,
		Error:        repairResult.Error,
	}
}
