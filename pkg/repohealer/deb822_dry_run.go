package repohealer

import "strings"

type Deb822RepairDryRunResult struct {
	Ready                bool
	Reason               string
	ActionID             string
	FindingCode          string
	ProfileID            string
	ProfileDisplayName   string
	RepositoryURL        string
	SourceFile           string
	KeyringPath          string
	RenderedSource       string
	SnapshotTargets      []string
	ExpectedFingerprints []string
}

func PreviewDeb822Repair(
	inspection Deb822RepairInspection,
	request Deb822RepairExecutionRequest,
) Deb822RepairDryRunResult {
	result := Deb822RepairDryRunResult{
		ActionID:             request.ActionID,
		FindingCode:          request.FindingCode,
		ProfileID:            request.ProfileID,
		ProfileDisplayName:   request.ProfileDisplayName,
		RepositoryURL:        request.RepositoryURL,
		SourceFile:           request.SourceFile,
		KeyringPath:          request.KeyringPath,
		RenderedSource:       request.RenderedSource,
		SnapshotTargets:      append([]string(nil), request.SnapshotTargets...),
		ExpectedFingerprints: append([]string(nil), request.ExpectedFingerprints...),
	}

	if err := validateDeb822ApprovalBinding(inspection, request); err != nil {
		result.Reason = strings.TrimSpace(err.Error())
		return result
	}

	result.Ready = true
	return result
}
