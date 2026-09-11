package playbook

import (
	"fmt"
	"strings"

	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

func RunSelectedDeb822DoctorRemoteCommand(
	client *ssh.Client,
	facts repohealer.TargetFacts,
	action repohealer.RepairAction,
	format Deb822DoctorOutputFormat,
) (Deb822DoctorCommandResult, error) {
	switch format {
	case Deb822DoctorOutputFormatText, Deb822DoctorOutputFormatJSON, "":
	default:
		return Deb822DoctorCommandResult{
			ExitCode: repohealer.Deb822DoctorExitUnknown,
		}, fmt.Errorf("unsupported Deb822 Doctor output format %q", format)
	}

	if client == nil {
		return Deb822DoctorCommandResult{
			ExitCode: repohealer.Deb822DoctorExitUnknown,
		}, fmt.Errorf("remote client is nil")
	}

	service, err := repohealer.RunSelectedDeb822DoctorRemoteService(
		repoHealerExecutor{client: client},
		facts,
		action,
	)
	if err != nil {
		return Deb822DoctorCommandResult{
			Report:   service.Report,
			ExitCode: repohealer.Deb822DoctorExitUnknown,
		}, fmt.Errorf("run selected remote Deb822 Doctor command: %w", err)
	}

	result := Deb822DoctorCommandResult{
		ExitCode: service.ExitCode,
		Report:   service.Report,
	}

	switch format {
	case Deb822DoctorOutputFormatText, "":
		result.Output = repohealer.FormatDeb822DoctorReport(service.Report)
	case Deb822DoctorOutputFormatJSON:
		result.Output = string(service.JSON)
	}

	return result, nil
}

func runSelectedDeb822DoctorRemoteFlow(
	client *ssh.Client,
	result repohealer.Result,
) {
	actions := blockedDeb822DoctorActions(result.Actions)
	if len(actions) == 0 {
		fmt.Println(
			Yellow +
				"[!] No discovered blocked Deb822 actions are eligible for remote Doctor. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println(Cyan + Bold + "\nAvailable read-only Deb822 Doctor targets:" + Reset)
	for index, action := range actions {
		fmt.Printf(
			"  [%d] %s — %s (blocked; read-only Doctor)\n",
			index+1,
			action.ID,
			action.ProfileDisplayName,
		)
	}

	selection := strings.TrimSpace(
		transfer.ReadRealtimeInput(
			"Select one Doctor target [1-" +
				fmt.Sprintf("%d", len(actions)) +
				"] or 0 to cancel: ",
		),
	)

	selectedAction, selected := selectRepositoryRepairAction(actions, selection)
	if !selected {
		fmt.Println(
			Yellow +
				"[!] Remote Deb822 Doctor selection canceled or invalid. No system changes were made." +
				Reset,
		)
		return
	}

	doctorResult, err := RunSelectedDeb822DoctorRemoteCommand(
		client,
		result.Target,
		selectedAction,
		Deb822DoctorOutputFormatText,
	)

	if doctorResult.Output != "" {
		fmt.Println("\n" + doctorResult.Output)
	}
	fmt.Printf(
		Cyan+"Remote Deb822 Doctor exit code: %d\n"+Reset,
		doctorResult.ExitCode,
	)

	if err != nil {
		fmt.Println(
			Yellow +
				fmt.Sprintf("[!] Remote Deb822 Doctor failed: %v", err) +
				Reset,
		)
		return
	}

	fmt.Println(
		Yellow +
			"[SAFE MODE] Remote Deb822 Doctor completed read-only checks. No system changes were made." +
			Reset,
	)
}
