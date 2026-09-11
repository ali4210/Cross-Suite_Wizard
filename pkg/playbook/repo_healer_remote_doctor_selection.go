package playbook

import "cross-ssh/pkg/repohealer"

func blockedDeb822DoctorActions(
	actions []repohealer.RepairAction,
) []repohealer.RepairAction {
	eligible := make([]repohealer.RepairAction, 0, len(actions))

	for _, action := range actions {
		if action.Eligible ||
			action.RequiresConsent ||
			action.SourceFormat != repohealer.SourceFormatDeb822 {
			continue
		}

		profile, ok := repohealer.FindVendorProfile(
			repohealer.ManagerAPT,
			action.RepositoryURL,
		)
		if !ok || profile.ID != action.ProfileID {
			continue
		}

		eligible = append(eligible, action)
	}

	return eligible
}
