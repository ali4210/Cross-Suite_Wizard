package repohealer

import "fmt"

func BuildRepairPlan(result Result) []RepairAction {
	actions := make([]RepairAction, 0)

	for _, finding := range result.Findings {
		if finding.Code != "APT_KEYRING_PATH_MISSING" {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, finding.RepositoryURL)
		if !ok {
			continue
		}

		actions = append(actions, RepairAction{
			ID:          "apt-keyring-repair-" + profile.ID,
			FindingCode: finding.Code,
			Risk:        RiskKnownVendor,
			Description: fmt.Sprintf(
				"Restore the missing repository-scoped keyring for %s and rewrite only %s.",
				profile.DisplayName,
				profile.SourceFile,
			),
			Commands: []string{
				"Create an APT configuration snapshot before mutation.",
				"Create /etc/apt/keyrings with mode 0755 if missing.",
				"Download the pinned key from: " + profile.KeyURL,
				"Verify the key against the profile's full GPG fingerprint list.",
				"Write keyring: " + profile.KeyringPath,
				"Write source file: " + profile.SourceFile,
				"Run apt-get update for final verification.",
			},
			Verification: []string{
				"apt-get update",
				"Confirm the targeted NO_PUBKEY error no longer appears.",
			},
			Rollback: []string{
				"Restore the source and keyring files from the pre-repair snapshot.",
			},
			RequiresConsent: true,
		})
	}

	return actions
}
