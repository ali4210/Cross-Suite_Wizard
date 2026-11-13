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

func runSelectedRepositoryRepairFlow(
	client *ssh.Client,
	result repohealer.Result,
) {
	if len(result.Actions) == 0 {
		fmt.Println(
			Yellow +
				"[!] No known-vendor APT repair actions were found. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println(Cyan + Bold + "\nAvailable repository repair actions:" + Reset)
	for index, action := range result.Actions {
		status := "eligible — approval required"
		if !action.Eligible {
			status = blockedRepositoryRepairActionStatusLabel(action)
		}

		fmt.Printf(
			"  [%d] %s — %s (%s)\n",
			index+1,
			action.ID,
			action.ProfileDisplayName,
			status,
		)
	}

	selection := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Select one repair action [1-" +
				fmt.Sprintf("%d", len(result.Actions)) +
				"] or 0 to cancel: ",
		),
	)

	if selection == "" ||
		selection == "0" ||
		strings.EqualFold(selection, "q") ||
		strings.EqualFold(selection, "back") {
		fmt.Println(
			Yellow +
				"[!] Repair selection canceled. No system changes were made." +
				Reset,
		)
		return
	}

	selectedAction, selected := selectRepositoryRepairAction(
		result.Actions,
		selection,
	)
	if !selected {
		fmt.Println(
			Yellow +
				"[!] Invalid repair action selection. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println("\n" + repohealer.FormatRepairAction(selectedAction))

	if !selectedAction.Eligible {
		if shouldRouteThroughAPTListRepairFlow(selectedAction) {
			runSelectedAPTListRepairExecutionFlow(client, result, selectedAction)
			return
		}

		doctor := repohealer.DiagnoseSelectedDeb822RepairRemoteReadiness(
			repoHealerExecutor{client: client},
			result.Target,
			selectedAction,
		)
		fmt.Println("\n" + repohealer.FormatDeb822DoctorReport(doctor))

		if !canProceedToDeb822Inspection(doctor) {
			fmt.Println(
				Yellow +
					"[BLOCKED] Deb822 Doctor did not permit inspection. No system changes were made." +
					Reset,
			)
			return
		}

		inspection, inspected := inspectSelectedDeb822Repair(
			client,
			result,
			selectedAction,
		)
		if inspected {
			fmt.Println(
				Cyan +
					"\n[INSPECTION] Reading and validating the approved Deb822 source before any repair decision." +
					Reset,
			)
			fmt.Println(
				"\n" + repohealer.FormatDeb822RepairInspection(inspection),
			)

			if !inspection.Ready {
				fmt.Println(
					Yellow +
						"[BLOCKED] Deb822 inspection did not produce a safe execution request. No system changes were made." +
						Reset,
				)
				return
			}

			runSelectedDeb822RepairExecutionFlow(
				client,
				selectedAction,
				inspection,
			)
			return
		}

		fmt.Println(
			Yellow +
				"[BLOCKED] This repair action is not approved for the detected target. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println(
		Red + Bold +
			"\n[!] APPLY MODE: The selected action may modify only the displayed repository source/keyring files." +
			Reset,
	)
	fmt.Println(
		Yellow +
			"    A targeted pre-repair snapshot will be created before any modification." +
			Reset,
	)

	confirmation := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type yes to apply this exact repair, or anything else to cancel: ",
		),
	)

	execution := repohealer.ApproveAndApplyAPTRepair(
		repoHealerExecutor{client: client},
		result,
		selectedAction.ID,
		confirmation,
	)

	fmt.Println("\n" + repohealer.FormatApprovalExecutionResult(execution))

	audit := repohealer.BuildRepairAuditEvent(execution, time.Now())
	fmt.Printf(
		Cyan+"Audit event: decision=%s failure_category=%s\n"+Reset,
		audit.Decision,
		audit.FailureCategory,
	)

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
		fmt.Printf(Cyan+"Audit record written: %s\n"+Reset, auditPath)
	}

	recordSnapshotHistory(
		client,
		"Option 7 mode [2]",
		execution.Action.ID,
		execution.RepairResult.Snapshot.ID,
		execution.RepairResult.Snapshot.Path,
		[]string{execution.Action.SourceFile, execution.Action.KeyringPath},
		result.Target.PackageManager,
		"",
		snapshotHistoryResultForApprovalExecution(execution),
	)
}

// snapshotHistoryResultForApprovalExecution maps the generic known-vendor APT repair's own
// decision/applied/rolled-back state onto Option 9's shared history result vocabulary.
func snapshotHistoryResultForApprovalExecution(execution repohealer.ApprovalExecutionResult) string {
	switch execution.Decision {
	case repohealer.ApprovalExecutionBlocked, repohealer.ApprovalExecutionActionNotFound:
		return repohealer.SnapshotHistoryResultBlocked
	case repohealer.ApprovalExecutionDeclined:
		return repohealer.SnapshotHistoryResultDeclined
	case repohealer.ApprovalExecutionExecuted:
		if execution.RepairResult.Applied {
			return repohealer.SnapshotHistoryResultApplied
		}
		if execution.RepairResult.RolledBack {
			return repohealer.SnapshotHistoryResultRolledBack
		}
		return repohealer.SnapshotHistoryResultFailed
	default:
		return repohealer.SnapshotHistoryResultFailed
	}
}

func canProceedToDeb822Inspection(
	report repohealer.Deb822DoctorReport,
) bool {
	return report.CanPreview
}

func inspectSelectedDeb822Repair(
	client *ssh.Client,
	result repohealer.Result,
	action repohealer.RepairAction,
) (repohealer.Deb822RepairInspection, bool) {
	if action.Eligible ||
		action.RequiresConsent ||
		action.SourceFormat != repohealer.SourceFormatDeb822 {
		return repohealer.Deb822RepairInspection{}, false
	}

	profile, ok := repohealer.FindVendorProfile(
		repohealer.ManagerAPT,
		action.RepositoryURL,
	)
	if !ok || profile.ID != action.ProfileID {
		return repohealer.Deb822RepairInspection{}, false
	}

	findingMatched := false
	for _, finding := range result.Findings {
		if finding.Code == action.FindingCode &&
			finding.RepositoryURL == action.RepositoryURL &&
			finding.SourceFile == action.SourceFile &&
			finding.SourceLine == action.SourceLine &&
			finding.SourceFormat == action.SourceFormat {
			findingMatched = true
			break
		}
	}

	if !findingMatched {
		return repohealer.Deb822RepairInspection{}, false
	}

	inspectionAction := action
	inspectionAction.Eligible = true
	inspectionAction.RequiresConsent = true

	inspection := repohealer.InspectApprovedDeb822Repair(
		repoHealerExecutor{client: client},
		inspectionAction,
		profile,
	)

	return inspection, true
}

func runSelectedDeb822RepairExecutionFlow(
	client *ssh.Client,
	action repohealer.RepairAction,
	inspection repohealer.Deb822RepairInspection,
) {
	request, err := prepareSelectedDeb822RepairExecution(
		action,
		inspection,
	)
	if err != nil {
		fmt.Println(
			Yellow +
				"[BLOCKED] Deb822 execution request could not be prepared. No system changes were made." +
				Reset,
		)
		fmt.Println(Yellow + "Reason: " + err.Error() + Reset)
		return
	}

	preview := repohealer.PreviewDeb822Repair(inspection, request)
	fmt.Println("\n" + repohealer.FormatDeb822RepairDryRun(preview))

	auditPath := repohealer.Deb822RepairAuditPath()
	previewAudit := repohealer.BuildDeb822RepairPreviewAuditEvent(
		preview,
		time.Now(),
	)
	if err := repohealer.AppendDeb822RepairPreviewAuditEvent(
		auditPath,
		previewAudit,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+
				"WARNING: Deb822 preview was completed, but its audit event could not be persisted to %q: %v\n"+
				Reset,
			auditPath,
			err,
		)
	} else {
		fmt.Printf(
			Cyan+
				"Preview audit record written: %s (ready=%t)\n"+
				Reset,
			auditPath,
			previewAudit.Ready,
		)
	}

	if !preview.Ready {
		return
	}

	mode := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type a, y, or yes to continue to apply confirmation, or press Enter to exit after preview: ",
		),
	)
	if !shouldContinueGatedRepairAfterPreview(mode) {
		fmt.Println(
			Yellow +
				"[PREVIEW COMPLETE] No system changes were made." +
				Reset,
		)
		return
	}

	if !printOperatorPolicyGateIfDisabled(
		repohealer.Deb822RepairExecutionEnabledEnv,
		repohealer.Deb822RepairExecutionEnabled(),
	) {
		execution := repohealer.Deb822RepairApprovalResult{
			Status:      repohealer.Deb822RepairApprovalStatusBlocked,
			ActionID:    request.ActionID,
			ProfileID:   request.ProfileID,
			SourceFile:  request.SourceFile,
			KeyringPath: request.KeyringPath,
			Reason: fmt.Sprintf(
				"Deb822 repair execution is disabled by operator policy; set %s=true only for approved maintenance",
				repohealer.Deb822RepairExecutionEnabledEnv,
			),
		}
		fmt.Println("\n" + repohealer.FormatDeb822RepairApprovalResult(execution))

		audit := repohealer.BuildDeb822RepairAuditEvent(execution, time.Now())
		if err := repohealer.AppendDeb822RepairAuditEvent(auditPath, audit); err != nil {
			fmt.Fprintf(
				os.Stderr,
				Yellow+
					"WARNING: Deb822 repair outcome was completed, but its audit event could not be persisted to %q: %v\n"+
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
			"\n[!] APPLY MODE: The reviewed Deb822 repair may modify only the displayed source and keyring files." +
			Reset,
	)
	fmt.Println(
		Yellow +
			"    A targeted two-file snapshot will be created before any modification, followed by apt-get update verification." +
			Reset,
	)

	confirmation := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Type yes to apply this exact reviewed Deb822 repair, or anything else to cancel: ",
		),
	)

	execution := repohealer.ApproveAndApplyDeb822Repair(
		repoHealerExecutor{client: client},
		inspection,
		request,
		confirmation,
	)

	fmt.Println("\n" + repohealer.FormatDeb822RepairApprovalResult(execution))

	audit := repohealer.BuildDeb822RepairAuditEvent(execution, time.Now())
	if err := repohealer.AppendDeb822RepairAuditEvent(auditPath, audit); err != nil {
		fmt.Fprintf(
			os.Stderr,
			Yellow+
				"WARNING: Deb822 repair outcome was completed, but its audit event could not be persisted to %q: %v\n"+
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

	recordSnapshotHistory(
		client,
		"Option 7 mode [2]",
		execution.ActionID,
		execution.ApplyResult.Snapshot.ID,
		execution.ApplyResult.Snapshot.Path,
		[]string{execution.SourceFile, execution.KeyringPath},
		repohealer.ManagerAPT,
		"",
		snapshotHistoryResultForDeb822(execution.Status, execution.ApplyResult.RolledBack),
	)
}

// snapshotHistoryResultForDeb822 maps the Deb822 repair's own approval status onto Option 9's
// shared history result vocabulary.
func snapshotHistoryResultForDeb822(status repohealer.Deb822RepairApprovalStatus, rolledBack bool) string {
	switch status {
	case repohealer.Deb822RepairApprovalStatusApplied:
		return repohealer.SnapshotHistoryResultApplied
	case repohealer.Deb822RepairApprovalStatusDeclined:
		return repohealer.SnapshotHistoryResultDeclined
	case repohealer.Deb822RepairApprovalStatusBlocked:
		return repohealer.SnapshotHistoryResultBlocked
	default:
		if rolledBack {
			return repohealer.SnapshotHistoryResultRolledBack
		}
		return repohealer.SnapshotHistoryResultFailed
	}
}

func appendDeb822RepairAudit(
	auditPath string,
	audit repohealer.Deb822RepairAuditEvent,
) error {
	return repohealer.AppendDeb822RepairAuditEvent(auditPath, audit)
}

// shouldContinueGatedRepairAfterPreview decides, for the "continue past preview to apply
// confirmation" prompt shared by every gated repair flow (Deb822, HashiCorp APT-list,
// fix-broken), whether the operator's response means "continue". It accepts "a", "y", or "yes"
// case-insensitively; anything else, including an empty (Enter) response, exits after preview
// with no system changes. Accepting "yes" here does not weaken anything: it only reaches the
// SAME apply-confirmation prompt that still requires its own separate typed "yes"/"y" before
// anything is actually applied — it just stops a plain-English "yes" from being silently
// treated as "exit", which is confusing at a prompt that reads like a yes/no question.
func shouldContinueGatedRepairAfterPreview(input string) bool {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "a", "y", "yes":
		return true
	default:
		return false
	}
}

// printOperatorPolicyGateIfDisabled prints a plain-language BLOCKED message naming the exact
// operator-policy environment variable and a sudo-safe example command, before the operator is
// ever asked to type a confirmation that would be rejected anyway. It returns whether the
// caller may proceed to ask for that confirmation. This is purely a UX improvement — each
// gated repair's own Approve/Apply function independently re-checks the same policy before
// doing anything, so skipping the prompt here never weakens the underlying gate.
func printOperatorPolicyGateIfDisabled(envVar string, enabled bool) bool {
	if enabled {
		return true
	}

	fmt.Println(
		Yellow +
			fmt.Sprintf(
				"[BLOCKED] This repair requires operator policy %s=true. No system changes were made.",
				envVar,
			) +
			Reset,
	)
	fmt.Println(
		Yellow +
			fmt.Sprintf("  Example: sudo %s=true ./autorun.sh", envVar) +
			Reset,
	)

	return false
}

// shouldRouteThroughAPTListRepairFlow decides, for a blocked repository repair action, whether
// it must go through the legacy APT-list Doctor/Preview/Apply path (e.g. HashiCorp's
// sources.list.d/hashicorp.list) instead of the Deb822 Doctor/Inspection path. A ".list" action
// must never be diagnosed through the Deb822 readiness report.
func shouldRouteThroughAPTListRepairFlow(action repohealer.RepairAction) bool {
	return action.SourceFormat == repohealer.SourceFormatAPTList
}

// blockedRepositoryRepairActionStatusLabel names which repair path a blocked action will route
// through, so the Option 7 mode [2] menu makes that explicit before the operator selects it.
func blockedRepositoryRepairActionStatusLabel(action repohealer.RepairAction) string {
	switch action.SourceFormat {
	case repohealer.SourceFormatAPTList:
		return "blocked — via the APT-list Doctor/Preview/Apply path"
	case repohealer.SourceFormatDeb822:
		return "blocked — via the Deb822 Doctor/Inspection path"
	default:
		return "blocked"
	}
}
