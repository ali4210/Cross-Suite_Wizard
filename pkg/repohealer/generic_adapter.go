package repohealer

import (
	"fmt"
	"strings"
)

// GenericAdapter is implemented by package-manager adapters that don't need APT's
// vendor-profile/signed-by machinery: they diagnose known failure signatures for their
// manager and propose ready-to-run RepairActions (Commands/Verification/Rollback already
// filled in) directly, instead of resolving a vendor profile at apply time.
type GenericAdapter interface {
	Manager() PackageManager
	Diagnose(exec Executor, facts TargetFacts, policy Policy) ([]CommandEvidence, []Finding, []RepairAction)
}

// ApproveAndApplyGenericRepair runs a RepairAction produced by a GenericAdapter: it requires
// explicit "yes" approval, snapshots any SnapshotTargets, runs Commands, verifies with
// Verification, and rolls back via the snapshot (or the action's own Rollback commands, if
// it has no file-based SnapshotTargets) when verification fails.
func ApproveAndApplyGenericRepair(
	exec Executor,
	actions []RepairAction,
	actionID string,
	response string,
) ApprovalExecutionResult {
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
			Error:    fmt.Errorf("repair action %q is blocked: %s", selected.ID, selected.BlockReason),
		}
	}

	if !IsRepairApproved(selected, response) {
		return ApprovalExecutionResult{
			Decision: ApprovalExecutionDeclined,
			Action:   selected,
			Error:    fmt.Errorf("repair action %q was not explicitly approved", selected.ID),
		}
	}

	repairResult := applyGenericRepairAction(exec, selected)

	return ApprovalExecutionResult{
		Decision:     ApprovalExecutionExecuted,
		Action:       selected,
		RepairResult: repairResult,
		Error:        repairResult.Error,
	}
}

func applyGenericRepairAction(exec Executor, action RepairAction) RepairResult {
	result := RepairResult{Attempted: true}

	// Homebrew refuses to run as root, so its actions are marked RunAsNonRoot and must
	// go through the plain (non-sudo) execution channel instead of RunSudo.
	runCmd := exec.RunSudo
	if action.RunAsNonRoot {
		runCmd = exec.Run
	}

	if len(action.SnapshotTargets) > 0 {
		snapshot, err := CreateAPTFileSnapshot(exec, action.SnapshotTargets)
		result.Snapshot = snapshot
		if err != nil || !snapshot.Created {
			result.Error = fmt.Errorf("pre-repair snapshot failed: %w", err)
			return result
		}
	}

	var outputs []string
	for _, cmd := range action.Commands {
		out, err := runCmd(cmd)
		outputs = append(outputs, out)
		if err != nil {
			result.Output = strings.Join(outputs, "\n")
			result.Error = fmt.Errorf("command failed: %s: %w", cmd, err)
			rollbackGenericRepair(exec, action, &result)
			return result
		}
	}
	result.Output = strings.Join(outputs, "\n")

	var verifyOutputs []string
	verificationFailed := false
	for _, cmd := range action.Verification {
		out, err := runCmd(cmd)
		verifyOutputs = append(verifyOutputs, out)
		if err != nil {
			verificationFailed = true
		}
	}
	result.VerificationOut = strings.Join(verifyOutputs, "\n")

	if verificationFailed {
		result.Error = fmt.Errorf("post-repair verification failed")
		rollbackGenericRepair(exec, action, &result)
		return result
	}

	result.Applied = true
	return result
}

func rollbackGenericRepair(exec Executor, action RepairAction, result *RepairResult) {
	if result.Snapshot.Created {
		if rbErr := RestoreAPTFileSnapshot(exec, result.Snapshot, action.SnapshotTargets); rbErr == nil {
			result.RolledBack = true
		}
		return
	}

	if len(action.Rollback) == 0 {
		return
	}
	for _, cmd := range action.Rollback {
		_, _ = exec.RunSudo(cmd)
	}
	result.RolledBack = true
}
