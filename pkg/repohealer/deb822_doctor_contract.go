package repohealer

import (
	"encoding/json"
	"fmt"
)

const (
	Deb822DoctorExitReady       = 0
	Deb822DoctorExitWarning     = 10
	Deb822DoctorExitBlocked     = 20
	Deb822DoctorExitUnsupported = 30
	Deb822DoctorExitUnknown     = 40
)

func Deb822DoctorExitCode(status Deb822DoctorStatus) int {
	switch status {
	case Deb822DoctorStatusReady:
		return Deb822DoctorExitReady
	case Deb822DoctorStatusWarning:
		return Deb822DoctorExitWarning
	case Deb822DoctorStatusBlocked:
		return Deb822DoctorExitBlocked
	case Deb822DoctorStatusUnsupported:
		return Deb822DoctorExitUnsupported
	default:
		return Deb822DoctorExitUnknown
	}
}

func MarshalDeb822DoctorReportJSON(
	report Deb822DoctorReport,
) ([]byte, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal Deb822 Doctor report: %w", err)
	}

	return encoded, nil
}
