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
			status = "blocked"
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
			"Type a to continue to apply confirmation, or press Enter to exit after preview: ",
		),
	)
	if !shouldContinueDeb822RepairAfterPreview(mode) {
		fmt.Println(
			Yellow +
				"[PREVIEW COMPLETE] No system changes were made." +
				Reset,
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
}

func appendDeb822RepairAudit(
	auditPath string,
	audit repohealer.Deb822RepairAuditEvent,
) error {
	return repohealer.AppendDeb822RepairAuditEvent(auditPath, audit)
}

func shouldContinueDeb822RepairAfterPreview(input string) bool {
	return strings.EqualFold(strings.TrimSpace(input), "a")
}
