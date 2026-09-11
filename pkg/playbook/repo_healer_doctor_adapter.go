package playbook

import (
	"fmt"

	"cross-ssh/pkg/repohealer"
)

type Deb822DoctorOutputFormat string

const (
	Deb822DoctorOutputFormatText Deb822DoctorOutputFormat = "text"
	Deb822DoctorOutputFormatJSON Deb822DoctorOutputFormat = "json"
)

type Deb822DoctorCommandResult struct {
	Output   string
	ExitCode int
	Report   repohealer.Deb822DoctorReport
}

func RunDeb822DoctorCommand(
	facts repohealer.TargetFacts,
	profileID string,
	format Deb822DoctorOutputFormat,
) (Deb822DoctorCommandResult, error) {
	service, err := repohealer.RunDeb822DoctorService(facts, profileID)
	if err != nil {
		return Deb822DoctorCommandResult{
			Report:   service.Report,
			ExitCode: repohealer.Deb822DoctorExitUnknown,
		}, fmt.Errorf("run Deb822 Doctor command: %w", err)
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
	default:
		return Deb822DoctorCommandResult{
			Report:   service.Report,
			ExitCode: repohealer.Deb822DoctorExitUnknown,
		}, fmt.Errorf("unsupported Deb822 Doctor output format %q", format)
	}

	return result, nil
}
