package playbook

import (
	"fmt"
	"os"
	"strings"
	"time"

	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"
)

// runAPTFixBrokenRepairFlow is Option 7 mode [5]: a read-only preview of "apt --fix-broken
// install" (the real dpkg --audit output plus the exact apt-get -s simulated plan), followed by
// a gated apply that requires the exact typed confirmation phrase (not a bare "yes", since this
// can install/remove/downgrade packages across the system), the operator-policy env flag, and
// the same disk/clock/dpkg safety gate the other gated repairs use. It never unholds a package.
func runAPTFixBrokenRepairFlow(exec repohealer.Executor) {
	fmt.Println(Cyan + Bold + "\n[+] APT Fix-Broken-Install: building a read-only preview..." + Reset)

	preview, err := repohealer.BuildAPTFixBrokenPreview(exec)
	if err != nil {
		fmt.Println(
			Yellow +
				fmt.Sprintf(
					"[BLOCKED] Could not build the fix-broken-install preview: %v. No system changes were made.",
					err,
				) +
				Reset,
		)
		return
	}

	fmt.Println("\n" + repohealer.FormatAPTFixBrokenPreview(preview))

	if preview.NothingToRepair {
		return
	}

	if !preview.Ready {
		fmt.Println(
			Yellow +
				"[BLOCKED] " + preview.Reason + " No system changes were made." +
				Reset,
		)
		return
	}

	mode := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type a, y, or yes to continue to apply confirmation, or press Enter to exit after preview: ",
		),
	)
	if !shouldContinueGatedRepairAfterPreview(mode) {
		fmt.Println(Yellow + "[PREVIEW COMPLETE] No system changes were made." + Reset)
		return
	}

	auditPath := repohealer.APTFixBrokenAuditPath()

	if !printOperatorPolicyGateIfDisabled(
		repohealer.APTFixBrokenRepairExecutionEnabledEnv,
		repohealer.APTFixBrokenRepairExecutionEnabled(),
	) {
		execution := repohealer.APTFixBrokenApprovalResult{
			Status: repohealer.APTFixBrokenApprovalStatusBlocked,
			Reason: fmt.Sprintf(
				"APT fix-broken repair execution is disabled by operator policy; set %s=true only for approved maintenance",
				repohealer.APTFixBrokenRepairExecutionEnabledEnv,
			),
		}
		fmt.Println("\n" + repohealer.FormatAPTFixBrokenApprovalResult(execution))
		appendAPTFixBrokenRepairAudit(auditPath, execution)
		return
	}

	fmt.Println(
		Red + Bold +
			"\n[!] APPLY MODE: 'apt --fix-broken install' may install, remove, or downgrade packages as shown above." +
			Reset,
	)
	fmt.Println(
		Yellow +
			"    A snapshot of the dpkg package database will be created first. No package will be unheld automatically." +
			Reset,
	)

	confirmation := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type FIX BROKEN PACKAGES (exact phrase) to apply, or anything else to cancel: ",
		),
	)

	execution := repohealer.ApproveAndApplyAPTFixBrokenRepair(exec, preview, confirmation)
	fmt.Println("\n" + repohealer.FormatAPTFixBrokenApprovalResult(execution))
	appendAPTFixBrokenRepairAudit(auditPath, execution)
}

func appendAPTFixBrokenRepairAudit(
	auditPath string,
	execution repohealer.APTFixBrokenApprovalResult,
) {
	audit := repohealer.BuildAPTFixBrokenAuditEvent(execution, time.Now())
	if err := repohealer.AppendAPTFixBrokenAuditEvent(auditPath, audit); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+
				"WARNING: APT fix-broken repair outcome was completed, but its audit event could not be persisted to %q: %v\n"+
				Reset,
			auditPath,
			err,
		)
	} else {
		fmt.Printf(
			Cyan+
				"Audit record written: %s (status=%s failure_category=%s)\n"+
				Reset,
			auditPath,
			audit.Status,
			audit.FailureCategory,
		)
	}
}
