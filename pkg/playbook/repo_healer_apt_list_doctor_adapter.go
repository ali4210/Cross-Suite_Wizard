package playbook

import (
	"fmt"

	"cross-ssh/pkg/repohealer"

	"golang.org/x/crypto/ssh"
)

type APTListDoctorCommandResult struct {
	Output   string
	ExitCode int
	Report   repohealer.APTListDoctorReport
}

func RunSelectedAPTListDoctorRemoteCommand(
	client *ssh.Client,
	facts repohealer.TargetFacts,
	action repohealer.RepairAction,
	format Deb822DoctorOutputFormat,
) (APTListDoctorCommandResult, error) {
	switch format {
	case Deb822DoctorOutputFormatText, Deb822DoctorOutputFormatJSON, "":
	default:
		return APTListDoctorCommandResult{
			ExitCode: repohealer.APTListDoctorExitUnknown,
		}, fmt.Errorf("unsupported APT list Doctor output format %q", format)
	}

	if client == nil {
		return APTListDoctorCommandResult{
			ExitCode: repohealer.APTListDoctorExitUnknown,
		}, fmt.Errorf("remote client is nil")
	}

	service, err := repohealer.RunSelectedAPTListDoctorRemoteService(
		repoHealerExecutor{client: client},
		facts,
		action,
	)
	if err != nil {
		return APTListDoctorCommandResult{
			Report:   service.Report,
			ExitCode: repohealer.APTListDoctorExitUnknown,
		}, fmt.Errorf("run selected remote APT list Doctor command: %w", err)
	}

	result := APTListDoctorCommandResult{
		ExitCode: service.ExitCode,
		Report:   service.Report,
	}

	switch format {
	case Deb822DoctorOutputFormatText, "":
		result.Output = repohealer.FormatAPTListDoctorReport(service.Report)
	case Deb822DoctorOutputFormatJSON:
		result.Output = string(service.JSON)
	}

	return result, nil
}
