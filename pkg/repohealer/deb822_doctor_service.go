package repohealer

import "fmt"

type Deb822DoctorServiceResult struct {
	Report   Deb822DoctorReport
	JSON     []byte
	ExitCode int
}

func RunDeb822DoctorService(
	facts TargetFacts,
	profileID string,
) (Deb822DoctorServiceResult, error) {
	report := DiagnoseDeb822RepairReadiness(facts, profileID)

	encoded, err := MarshalDeb822DoctorReportJSON(report)
	if err != nil {
		return Deb822DoctorServiceResult{
			Report:   report,
			ExitCode: Deb822DoctorExitUnknown,
		}, fmt.Errorf("build Deb822 Doctor service result: %w", err)
	}

	return Deb822DoctorServiceResult{
		Report:   report,
		JSON:     encoded,
		ExitCode: Deb822DoctorExitCode(report.Overall),
	}, nil
}
