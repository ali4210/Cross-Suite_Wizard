package repohealer

import (
	"encoding/json"
	"fmt"
)

type APTListDoctorStatus string

const (
	APTListDoctorStatusReady       APTListDoctorStatus = "ready"
	APTListDoctorStatusWarning     APTListDoctorStatus = "warning"
	APTListDoctorStatusBlocked     APTListDoctorStatus = "blocked"
	APTListDoctorStatusUnsupported APTListDoctorStatus = "unsupported"
	APTListDoctorStatusUnknown     APTListDoctorStatus = "unknown"
)

const (
	APTListDoctorExitReady       = 0
	APTListDoctorExitWarning     = 10
	APTListDoctorExitBlocked     = 20
	APTListDoctorExitUnsupported = 30
	APTListDoctorExitUnknown     = 40
)

const (
	HashiCorpAPTListProfileID = "hashicorp"

	HashiCorpAPTListRepositoryURL = "https://apt.releases.hashicorp.com"

	HashiCorpAPTListKeyringPath = "/usr/share/keyrings/hashicorp-archive-keyring.gpg"

	HashiCorpAPTListExpectedFingerprint = "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"
)

type APTListDoctorCheck struct {
	Name    string              `json:"name"`
	Status  APTListDoctorStatus `json:"status"`
	Message string              `json:"message"`
}

type APTListDoctorReport struct {
	Overall             APTListDoctorStatus  `json:"overall"`
	Target              TargetFacts          `json:"target"`
	ActionID            string               `json:"action_id,omitempty"`
	ProfileID           string               `json:"profile_id,omitempty"`
	RepositoryURL       string               `json:"repository_url,omitempty"`
	SourceFile          string               `json:"source_file,omitempty"`
	SourceLine          int                  `json:"source_line,omitempty"`
	KeyringPath         string               `json:"keyring_path,omitempty"`
	ExpectedFingerprint string               `json:"expected_fingerprint,omitempty"`
	Checks              []APTListDoctorCheck `json:"checks"`
	CanInspect          bool                 `json:"can_inspect"`
	CanPreview          bool                 `json:"can_preview"`
	CanApply            bool                 `json:"can_apply"`
}

func APTListDoctorExitCode(status APTListDoctorStatus) int {
	switch status {
	case APTListDoctorStatusReady:
		return APTListDoctorExitReady
	case APTListDoctorStatusWarning:
		return APTListDoctorExitWarning
	case APTListDoctorStatusBlocked:
		return APTListDoctorExitBlocked
	case APTListDoctorStatusUnsupported:
		return APTListDoctorExitUnsupported
	default:
		return APTListDoctorExitUnknown
	}
}

func APTListDoctorMutationAllowed(report APTListDoctorReport) bool {
	return false
}

func ValidateAPTListDoctorReport(
	report APTListDoctorReport,
) error {
	switch report.Overall {
	case APTListDoctorStatusReady,
		APTListDoctorStatusWarning,
		APTListDoctorStatusBlocked,
		APTListDoctorStatusUnsupported,
		APTListDoctorStatusUnknown:
		if report.CanInspect || report.CanPreview || report.CanApply {
			return fmt.Errorf(
				"%s APT list Doctor report must not permit inspection, preview, or apply",
				report.Overall,
			)
		}
		return nil
	default:
		return fmt.Errorf(
			"unknown APT list Doctor status %q",
			report.Overall,
		)
	}
}

func MarshalAPTListDoctorReportJSON(
	report APTListDoctorReport,
) ([]byte, error) {
	if err := ValidateAPTListDoctorReport(report); err != nil {
		return nil, fmt.Errorf("validate APT list Doctor report: %w", err)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal APT list Doctor report: %w", err)
	}

	return encoded, nil
}
