package playbook

import (
	"fmt"
	"os"
	"strings"
	"time"

	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// runSelectedGenericRepairFlow drives repair selection/approval/apply for every package
// manager adapter that isn't APT (dnf/yum, pacman, zypper, apk, xbps, Homebrew). Unlike the
// APT/Deb822 flow, these actions are self-contained (no vendor-profile lookup) and are
// applied through the generic repohealer.ApproveAndApplyGenericRepair orchestrator.
func runSelectedGenericRepairFlow(client *ssh.Client, result repohealer.Result) {
	if len(result.Actions) == 0 {
		fmt.Println(
			Yellow +
				"[!] No auto-repairable actions were found for this package manager. Review the findings above for manual guidance. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println(Cyan + Bold + "\nAvailable repair actions:" + Reset)
	for index, action := range result.Actions {
		status := "eligible — approval required"
		if !action.Eligible {
			status = "blocked: " + action.BlockReason
		}
		fmt.Printf("  [%d] %s — %s (%s)\n", index+1, action.ID, action.Description, status)
	}

	selection := strings.TrimSpace(
		transfer.ReadRealtimeInput(fmt.Sprintf(
			"Select one repair action [1-%d] or 0 to cancel: ",
			len(result.Actions),
		)),
	)
	if selection == "" || selection == "0" || strings.EqualFold(selection, "q") || strings.EqualFold(selection, "back") {
		fmt.Println(Yellow + "[!] Repair selection canceled. No system changes were made." + Reset)
		return
	}

	selectedAction, ok := selectRepositoryRepairAction(result.Actions, selection)
	if !ok {
		fmt.Println(Yellow + "[!] Invalid repair action selection. No system changes were made." + Reset)
		return
	}

	if !selectedAction.Eligible {
		fmt.Println(Yellow + "[BLOCKED] " + selectedAction.BlockReason + Reset)
		return
	}

	fmt.Println(Red + Bold + "\n[!] APPLY MODE: The selected action will run the following commands:" + Reset)
	for _, cmd := range selectedAction.Commands {
		fmt.Println("  $ " + cmd)
	}
	if selectedAction.UseHomebrewSnapshot {
		fmt.Println(Yellow + "    A pre-repair Homebrew snapshot (Brewfile) will be created, restorable via Option [9]." + Reset)
	} else if len(selectedAction.SnapshotTargets) > 0 {
		fmt.Println(Yellow + "    A pre-repair snapshot will be created for: " + strings.Join(selectedAction.SnapshotTargets, ", ") + Reset)
	}

	confirmation := strings.TrimSpace(
		transfer.ReadRealtimeInput("Type yes to apply this exact repair, or anything else to cancel: "),
	)

	execution := repohealer.ApproveAndApplyGenericRepair(
		repoHealerExecutor{client: client},
		result.Actions,
		selectedAction.ID,
		confirmation,
	)

	fmt.Println("\n" + repohealer.FormatApprovalExecutionResult(execution))

	audit := repohealer.BuildRepairAuditEvent(execution, time.Now())
	auditPath := repohealer.RepairAuditPath()
	if err := repohealer.AppendRepairAuditEvent(auditPath, audit); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+
				"WARNING: Repair outcome was completed, but its audit event could not be persisted to %q: %v\n"+
				Reset,
			auditPath,
			err,
		)
	} else {
		fmt.Printf(
			Cyan+"Audit record written: %s (decision=%s failure_category=%s)\n"+Reset,
			auditPath,
			audit.Decision,
			audit.FailureCategory,
		)
	}
}
