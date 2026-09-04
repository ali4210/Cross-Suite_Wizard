package repohealer

import "fmt"

func BuildRepairPlan(result Result) []RepairAction {
	actions := make([]RepairAction, 0)
	seenProfiles := make(map[string]bool)

	for _, finding := range result.Findings {
		if finding.Code != "APT_KEYRING_PATH_MISSING" {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, finding.RepositoryURL)
		if !ok || seenProfiles[profile.ID] {
			continue
		}

		seenProfiles[profile.ID] = true

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
				"Create a targeted APT source/keyring snapshot before mutation.",
				"Create /etc/apt/keyrings with mode 0755 if missing.",
				"Download the pinned key from: " + profile.KeyURL,
				"Verify the downloaded key against the profile's full GPG fingerprint list.",
				"Write keyring: " + profile.KeyringPath,
				"Render an architecture-aware and profile-validated source file: " + profile.SourceFile,
				"Run apt-get update for final verification.",
			},
			Verification: []string{
				"apt-get update",
				"Confirm the repository authentication error no longer appears.",
			},
			Rollback: []string{
				"Restore only the profile source/keyring files from the pre-repair snapshot.",
			},
			RequiresConsent: true,
		})
	}

	return actions
}
