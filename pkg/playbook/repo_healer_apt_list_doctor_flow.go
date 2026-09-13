package playbook

import (
	"fmt"
	"strings"

	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

func runSelectedAPTListDoctorRemoteFlow(
	client *ssh.Client,
	result repohealer.Result,
) {
	actions := blockedAPTListDoctorActions(result.Actions)
	if len(actions) == 0 {
		fmt.Println(
			Yellow +
				"[!] No discovered blocked HashiCorp APT-list actions are eligible for remote Doctor. No system changes were made." +
				Reset,
		)
		return
	}

	fmt.Println(
		Cyan + Bold +
			"\nAvailable read-only HashiCorp APT-list Doctor targets:" +
			Reset,
	)
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
				"[!] Remote HashiCorp APT-list Doctor selection canceled or invalid. No system changes were made." +
				Reset,
		)
		return
	}

	doctorResult, err := RunSelectedAPTListDoctorRemoteCommand(
		client,
		result.Target,
		selectedAction,
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
				fmt.Sprintf("[!] Remote HashiCorp APT-list Doctor failed: %v", err) +
				Reset,
		)
		return
	}

	fmt.Println(
		Yellow +
			"[SAFE MODE] Remote HashiCorp APT-list Doctor completed read-only checks. No system changes were made." +
			Reset,
	)
}
