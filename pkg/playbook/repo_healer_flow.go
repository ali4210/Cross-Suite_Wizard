package playbook

import (
	"fmt"
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
					"\n[INSPECTION ONLY] Reading and validating the approved Deb822 source. No repair will run." +
					Reset,
			)
			fmt.Println(
				"\n" + repohealer.FormatDeb822RepairInspection(inspection),
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
