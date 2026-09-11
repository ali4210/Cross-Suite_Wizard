package playbook

import (
	"fmt"

	"cross-ssh/pkg/repohealer"

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
