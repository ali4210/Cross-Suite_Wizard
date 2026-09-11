package playbook

import (
	"fmt"

	"cross-ssh/pkg/repohealer"
)

func prepareSelectedDeb822RepairExecution(
	action repohealer.RepairAction,
	inspection repohealer.Deb822RepairInspection,
) (repohealer.Deb822RepairExecutionRequest, error) {
	if action.Eligible ||
		action.RequiresConsent ||
		action.SourceFormat != repohealer.SourceFormatDeb822 {
		return repohealer.Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution preparation blocked: selected action is not an original blocked Deb822 action",
		)
	}

	profile, ok := repohealer.FindVendorProfile(
		repohealer.ManagerAPT,
		action.RepositoryURL,
	)
	if !ok || profile.ID != action.ProfileID {
		return repohealer.Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution preparation blocked: selected action does not resolve to its verified APT vendor profile",
		)
	}

	request, err := repohealer.BuildDeb822RepairExecutionRequest(
		inspection,
		action,
		profile,
	)
	if err != nil {
		return repohealer.Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution preparation blocked: %w",
			err,
		)
	}

	return request, nil
}
