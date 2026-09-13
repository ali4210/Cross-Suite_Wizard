package repohealer

import "fmt"

type Deb822DoctorRemoteServiceResult struct {
	Report   Deb822DoctorReport
	JSON     []byte
	ExitCode int
}

func RunSelectedDeb822DoctorRemoteService(
	exec Executor,
	facts TargetFacts,
	action RepairAction,
) (Deb822DoctorRemoteServiceResult, error) {
	report := DiagnoseSelectedDeb822RepairRemoteReadiness(
		exec,
		facts,
		action,
	)

	encoded, err := MarshalDeb822DoctorReportJSON(report)
	if err != nil {
		return Deb822DoctorRemoteServiceResult{
			Report:   report,
			ExitCode: Deb822DoctorExitUnknown,
		}, fmt.Errorf("build remote Deb822 Doctor service result: %w", err)
	}

	return Deb822DoctorRemoteServiceResult{
		Report:   report,
		JSON:     encoded,
		ExitCode: Deb822DoctorExitCode(report.Overall),
	}, nil
}
