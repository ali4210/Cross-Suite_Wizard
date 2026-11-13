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

// runAPTFixBrokenRepairFlow is Option 7 mode [5]: a read-only preview of "apt --fix-broken
// install" (the real dpkg --audit output plus the exact apt-get -s simulated plan), followed by
// a gated apply that requires the exact typed confirmation phrase (not a bare "yes", since this
// can install/remove/downgrade packages across the system), the operator-policy env flag, and
// the same disk/clock/dpkg safety gate the other gated repairs use. It never unholds a package.
func runAPTFixBrokenRepairFlow(client *ssh.Client, exec repohealer.Executor) {
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
		recordSnapshotHistory(
			client,
			"Option 7 mode [5]",
			"apt-fix-broken-install",
			"",
			"",
			nil,
			repohealer.ManagerAPT,
			"",
			repohealer.SnapshotHistoryResultBlocked,
		)
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
	recordSnapshotHistory(
		client,
		"Option 7 mode [5]",
		"apt-fix-broken-install",
		execution.ApplyResult.Snapshot.ID,
		execution.ApplyResult.Snapshot.Path,
		[]string{"/var/lib/dpkg/status", "/var/lib/dpkg/status-old"},
		repohealer.ManagerAPT,
		"",
		snapshotHistoryResultForAPTFixBroken(execution.Status, execution.ApplyResult.RolledBack),
	)
}

// snapshotHistoryResultForAPTFixBroken maps the fix-broken repair's own approval status onto
// Option 9's shared history result vocabulary.
func snapshotHistoryResultForAPTFixBroken(
	status repohealer.APTFixBrokenApprovalStatus,
	rolledBack bool,
) string {
	switch status {
	case repohealer.APTFixBrokenApprovalStatusApplied:
		return repohealer.SnapshotHistoryResultApplied
	case repohealer.APTFixBrokenApprovalStatusDeclined:
		return repohealer.SnapshotHistoryResultDeclined
	case repohealer.APTFixBrokenApprovalStatusBlocked:
		return repohealer.SnapshotHistoryResultBlocked
	default:
		if rolledBack {
			return repohealer.SnapshotHistoryResultRolledBack
		}
		return repohealer.SnapshotHistoryResultFailed
	}
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
