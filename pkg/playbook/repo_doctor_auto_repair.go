package playbook

import (
	"fmt"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/repohealer"

	"golang.org/x/crypto/ssh"
)

// attemptAutoSafeRepoRepair is the "trigger the repo doctor and retry once" hook for
// Option 1 (Search/Install): when an install fails, it runs the same repohealer diagnose
// pass Option 7 uses and, if there is exactly one action the engine itself classified as
// RiskAutoSafe, applies it automatically (no interactive "yes" prompt — AutoSafe is the
// engine's own designation for changes safe to make without a human decision, such as
// clearing a stale lock or rebuilding a metadata cache) and reports what it did. It never
// auto-applies anything above that risk tier, and never runs for Windows (no bash engine
// there) or macOS (Homebrew's one offered fix needs the non-root channel, not worth the
// risk of auto-applying unattended).
func attemptAutoSafeRepoRepair(client *ssh.Client, targetOS osdetect.TargetOS) bool {
	if targetOS != osdetect.OSLinux {
		return false
	}

	exec := repoHealerExecutor{client: client}
	engine := repohealer.New(exec, targetOS, repohealer.DefaultDiagnosticPolicy())
	result := engine.Run()

	var safeAction *repohealer.RepairAction
	for i := range result.Actions {
		action := result.Actions[i]
		if action.Eligible && action.Risk == repohealer.RiskAutoSafe {
			safeAction = &result.Actions[i]
			break
		}
	}

	if safeAction == nil {
		fmt.Println(Yellow + "[!] Repository doctor found no known-safe automatic fix for this host." + Reset)
		return false
	}

	fmt.Println(Cyan + fmt.Sprintf("[+] Repository doctor found a known-safe fix: %s — applying it automatically.", safeAction.Description) + Reset)

	var execution repohealer.ApprovalExecutionResult
	if result.Target.PackageManager == repohealer.ManagerAPT {
		execution = repohealer.ApproveAndApplyAPTRepair(exec, result, safeAction.ID, "yes")
	} else {
		execution = repohealer.ApproveAndApplyGenericRepair(exec, result.Actions, safeAction.ID, "yes")
	}

	fmt.Println(repohealer.FormatApprovalExecutionResult(execution))

	audit := repohealer.BuildRepairAuditEvent(execution, time.Now())
	auditPath := repohealer.RepairAuditPath()
	_ = repohealer.AppendRepairAuditEvent(auditPath, audit)

	return execution.Decision == repohealer.ApprovalExecutionExecuted && execution.RepairResult.Applied
}
