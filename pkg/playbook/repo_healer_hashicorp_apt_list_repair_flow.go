package playbook

import (
	"fmt"

	"cross-ssh/pkg/repohealer"
)

func prepareSelectedHashiCorpAPTListRepair(
	action repohealer.RepairAction,
	preview repohealer.APTListRepairPreview,
	confirmation string,
) (repohealer.HashiCorpAPTListRepairExecutionRequest, error) {
	if action.Eligible ||
		action.RequiresConsent ||
		action.SourceFormat != repohealer.SourceFormatAPTList {
		return repohealer.HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair preparation blocked: selected action is not an original blocked HashiCorp APT-list action",
		)
	}

	if action.ProfileID != repohealer.HashiCorpAPTListProfileID {
		return repohealer.HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair preparation blocked: selected action does not resolve to the verified HashiCorp APT profile",
		)
	}

	profile, ok := repohealer.FindVendorProfileByID(
		repohealer.ManagerAPT,
		repohealer.HashiCorpAPTListProfileID,
	)
	if !ok || profile.ID != action.ProfileID {
		return repohealer.HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair preparation blocked: selected action does not resolve to the verified HashiCorp APT profile",
		)
	}

	request, err := repohealer.BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		confirmation,
	)
	if err != nil {
		return repohealer.HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair preparation blocked: %w",
			err,
		)
	}

	return request, nil
}
