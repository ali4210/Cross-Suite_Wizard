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

// runSelectedAPTListRepairExecutionFlow is Option 7 mode [2]'s path for a blocked HashiCorp
// APT-list action (SourceFormat apt-list): Doctor -> Preview -> typed continue -> preflight ->
// non-repository safety gate (disk/clock/dpkg) -> typed "yes" -> gated apply -> audit. A
// Deb822 action never reaches this function; see runSelectedRepositoryRepairFlow, which routes
// by SourceFormat via shouldRouteThroughAPTListRepairFlow. Unlike
// runSelectedAPTListDoctorRemoteFlow (the read-only Doctor-only mode), this flow can modify the
// target after explicit typed approval.
func runSelectedAPTListRepairExecutionFlow(
	client *ssh.Client,
	result repohealer.Result,
	action repohealer.RepairAction,
) {
	exec := repoHealerExecutor{client: client}

	doctorResult, err := RunSelectedAPTListDoctorRemoteCommand(
		client,
		result.Target,
		action,
		Deb822DoctorOutputFormatText,
	)

	if doctorResult.Output != "" {
		fmt.Println("\n" + doctorResult.Output)
	}
	fmt.Printf(
		Cyan+"Remote HashiCorp APT-list Doctor exit code: %d\n"+Reset,
		doctorResult.ExitCode,
	)

	if err != nil {
		fmt.Println(
			Yellow +
				fmt.Sprintf(
					"[BLOCKED] Remote HashiCorp APT-list Doctor failed: %v. Next step: confirm SSH/sudo access to the target and retry. No system changes were made.",
					err,
				) +
				Reset,
		)
		return
	}

	preview := repohealer.PreviewBlockedHashiCorpAPTListRepair(doctorResult.Report)
	fmt.Println("\n" + repohealer.FormatAPTListRepairPreview(preview))

	if !preview.Ready {
		fmt.Println(
			Yellow +
				"[BLOCKED] The APT-list Doctor did not produce a repair-ready preview. Next step: " +
				preview.Reason +
				". No system changes were made." +
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

	request, err := repohealer.BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		repohealer.HashiCorpAPTListRepairConfirmation,
	)
	if err != nil {
		fmt.Println(
			Yellow +
				"[BLOCKED] HashiCorp APT-list execution request could not be prepared. No system changes were made." +
				Reset,
		)
		fmt.Println(Yellow + "Reason: " + err.Error() + Reset)
		return
	}

	probe, err := repohealer.ProbeHashiCorpAPTListRepairPreflight(exec, request)
	if err != nil {
		fmt.Println(
			Yellow +
				fmt.Sprintf(
					"[BLOCKED] HashiCorp APT-list repair preflight probe failed: %v. Next step: confirm sudo access and required tools (apt-get, gpg, install, mv, sha256sum) on the target, then retry. No system changes were made.",
					err,
				) +
				Reset,
		)
		return
	}

	preflight := repohealer.EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		doctorResult.Report,
	)
	if !preflight.Ready {
		fmt.Println(
			Yellow +
				"[BLOCKED] " + preflight.Reason + " No system changes were made." +
				Reset,
		)
		return
	}

	safety := repohealer.EvaluateHashiCorpAPTListRepairSafety(exec)
	if blocked, reason := safety.Blocked(); blocked {
		fmt.Println(Yellow + reason + Reset)
		return
	}

	auditPath := repohealer.HashiCorpAPTListRepairAuditPath()

	if !printOperatorPolicyGateIfDisabled(
		repohealer.HashiCorpAPTListRepairExecutionEnabledEnv,
		repohealer.HashiCorpAPTListRepairExecutionEnabled(),
	) {
		execution := repohealer.HashiCorpAPTListRepairApprovalResult{
			Status:      repohealer.HashiCorpAPTListRepairApprovalStatusBlocked,
			ActionID:    request.ActionID,
			ProfileID:   request.ProfileID,
			SourceFile:  request.SourceFile,
			KeyringPath: request.KeyringPath,
			Reason: fmt.Sprintf(
				"HashiCorp APT-list repair execution is disabled by operator policy; set %s=true only for approved maintenance",
				repohealer.HashiCorpAPTListRepairExecutionEnabledEnv,
			),
		}
		fmt.Println("\n" + repohealer.FormatHashiCorpAPTListRepairApprovalResult(execution))
		appendHashiCorpAPTListRepairAudit(auditPath, execution)
		recordSnapshotHistory(
			client,
			"Option 7 mode [2]",
			execution.ActionID,
			"",
			"",
			[]string{execution.SourceFile, execution.KeyringPath},
			repohealer.ManagerAPT,
			"",
			repohealer.SnapshotHistoryResultBlocked,
		)
		return
	}

	fmt.Println(
		Red + Bold +
			"\n[!] APPLY MODE: The reviewed HashiCorp APT-list repair may replace only the displayed keyring file." +
			Reset,
	)
	fmt.Println(
		Yellow +
			"    A targeted snapshot of the source and keyring files will be created first, followed by apt-get update verification. Rollback is automatic on any failure." +
			Reset,
	)

	confirmation := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type yes to apply this exact reviewed HashiCorp APT-list repair, or anything else to cancel: ",
		),
	)

	execution := repohealer.ApproveAndApplyHashiCorpAPTListRepair(exec, preflight, confirmation)
	fmt.Println("\n" + repohealer.FormatHashiCorpAPTListRepairApprovalResult(execution))
	appendHashiCorpAPTListRepairAudit(auditPath, execution)
	recordSnapshotHistory(
		client,
		"Option 7 mode [2]",
		execution.ActionID,
		execution.ApplyResult.Snapshot.ID,
		execution.ApplyResult.Snapshot.Path,
		[]string{execution.SourceFile, execution.KeyringPath},
		repohealer.ManagerAPT,
		"",
		snapshotHistoryResultForHashiCorpAPTList(execution.Status, execution.ApplyResult.RolledBack),
	)
}

// snapshotHistoryResultForHashiCorpAPTList maps the HashiCorp APT-list repair's own approval
// status onto Option 9's shared history result vocabulary.
func snapshotHistoryResultForHashiCorpAPTList(
	status repohealer.HashiCorpAPTListRepairApprovalStatus,
	rolledBack bool,
) string {
	switch status {
	case repohealer.HashiCorpAPTListRepairApprovalStatusApplied:
		return repohealer.SnapshotHistoryResultApplied
	case repohealer.HashiCorpAPTListRepairApprovalStatusDeclined:
		return repohealer.SnapshotHistoryResultDeclined
	case repohealer.HashiCorpAPTListRepairApprovalStatusBlocked:
		return repohealer.SnapshotHistoryResultBlocked
	default:
		if rolledBack {
			return repohealer.SnapshotHistoryResultRolledBack
		}
		return repohealer.SnapshotHistoryResultFailed
	}
}

func appendHashiCorpAPTListRepairAudit(
	auditPath string,
	execution repohealer.HashiCorpAPTListRepairApprovalResult,
) {
	audit := repohealer.BuildHashiCorpAPTListRepairAuditEvent(execution, time.Now())
	if err := repohealer.AppendHashiCorpAPTListRepairAuditEvent(auditPath, audit); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+
				"WARNING: HashiCorp APT-list repair outcome was completed, but its audit event could not be persisted to %q: %v\n"+
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
