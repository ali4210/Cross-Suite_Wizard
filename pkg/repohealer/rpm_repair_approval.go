package repohealer

import "fmt"

// ApproveAndApplyRPMRepair mirrors ApproveAndApplyAPTRepair (approval_orchestrator.go) for
// the dnf/yum/zypper family, with one addition: the operator-policy gate
// (RPMRepairExecutionEnabled) is checked here, before IsRepairApproved even looks at the
// typed response — an operator who hasn't opted in for this host is blocked before their
// "yes" is evaluated at all, not just before the system is touched.
func ApproveAndApplyRPMRepair(
	exec Executor,
	result Result,
	actionID string,
	response string,
) ApprovalExecutionResult {
	actions := BuildRPMRepairPlan(result)

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

	if !RPMRepairExecutionEnabled() {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionBlocked,
			Action:   selected,
			Error: fmt.Errorf(
				"repair action %q is blocked: operator policy %s is not set to \"true\" on this host",
				selected.ID,
				RPMRepairExecutionEnabledEnv,
			),
		}
	}

	if !selected.Eligible {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionBlocked,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q is blocked: %s", selected.ID, selected.BlockReason),
		}
	}

	if !IsKnownRPMRepairFinding(selected.FindingCode) {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q has unsupported RPM finding code %q", selected.ID, selected.FindingCode),
		}
	}

	if !IsRepairApproved(selected, response) {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionDeclined,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q was not explicitly approved", selected.ID),
		}
	}

	profile, ok := FindVendorProfile(canonicalRPMManager(result.Target.PackageManager), selected.RepositoryURL)
	if !ok || profile.ID != selected.ProfileID {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q does not resolve to its approved RPM vendor profile", selected.ID),
		}
	}

	findingMatched := false
	for _, finding := range result.Findings {
		if finding.Code == selected.FindingCode &&
			finding.RepositoryURL == selected.RepositoryURL &&
			finding.SourceFile == selected.SourceFile {
			findingMatched = true
			break
		}
	}
	if !findingMatched {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionActionNotFound,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q no longer matches the diagnosis findings", selected.ID),
		}
	}

	repairResult := applyKnownRPMRepairActionWithVerification(exec, result.Target, profile, selected)

	return ApprovalExecutionResult{
		Decision:     ApprovalExecutionExecuted,
		Action:       selected,
		RepairResult: repairResult,
		Error:        repairResult.Error,
	}
}
