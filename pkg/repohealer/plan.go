package repohealer

import (
	"fmt"
	"strings"
)

func BuildRepairPlan(result Result) []RepairAction {
	actions := make([]RepairAction, 0)
	seenProfiles := make(map[string]bool)

	for _, finding := range result.Findings {
		if !IsKnownAPTRepairFinding(finding.Code) {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, finding.RepositoryURL)
		if !ok || seenProfiles[profile.ID] {
			continue
		}

		seenProfiles[profile.ID] = true

		action := RepairAction{
			ID:                   APTRepairActionID(profile.ID, finding.Code),
			FindingCode:          finding.Code,
			Risk:                 RiskKnownVendor,
			Description:          fmt.Sprintf("Prepare a repository-scoped APT trust repair plan for %s.", profile.DisplayName),
			Commands:             []string{},
			Verification:         []string{"apt-get update"},
			Rollback:             []string{"Restore only the profile source/keyring files from the pre-repair snapshot."},
			RequiresConsent:      true,
			Eligible:             true,
			ProfileID:            profile.ID,
			ProfileDisplayName:   profile.DisplayName,
			RepositoryURL:        finding.RepositoryURL,
			Target:               result.Target,
			KeyURL:               profile.KeyURL,
			ExpectedFingerprints: append([]string(nil), profile.ExpectedFingerprints...),
			KeyringPath:          profile.KeyringPath,
			SourceFile:           finding.SourceFile,
			SourceLine:           finding.SourceLine,
			SourceFormat:         finding.SourceFormat,
			SnapshotTargets: []string{
				profile.SourceFile,
				profile.KeyringPath,
			},
		}

		if finding.SourceFormat == SourceFormatDeb822 {
			action.Risk = RiskBlocked
			action.Description = fmt.Sprintf(
				"APT repair for %s is blocked because the detected source uses Deb822 format.",
				profile.DisplayName,
			)
			action.Commands = nil
			action.Verification = nil
			action.Rollback = nil
			action.RequiresConsent = false
			action.Eligible = false
			action.BlockReason = fmt.Sprintf(
				"Deb822 source repair requires a separate inspection and fresh explicit approval flow. The detected source file %s will remain in Deb822 format and will not be converted to the profile .list file %s.",
				finding.SourceFile,
				profile.SourceFile,
			)
			actions = append(actions, action)
			continue
		}

		if finding.SourceFormat != SourceFormatUnknown &&
			finding.SourceFormat != SourceFormatAPTList {
			action.Risk = RiskBlocked
			action.Description = fmt.Sprintf(
				"APT repair for %s is blocked because the source format is unsupported.",
				profile.DisplayName,
			)
			action.Commands = nil
			action.Verification = nil
			action.Rollback = nil
			action.RequiresConsent = false
			action.Eligible = false
			action.BlockReason = fmt.Sprintf(
				"Unsupported APT source format %q for %s.",
				finding.SourceFormat,
				finding.SourceFile,
			)
			actions = append(actions, action)
			continue
		}

		renderedSource, err := RenderAPTSource(profile, SourceRenderInput{
			Architecture: result.Target.Architecture,
			Distribution: result.Target.Distribution,
			Version:      result.Target.Version,
			Codename:     result.Target.Codename,
		})
		if err != nil {
			action.Risk = RiskBlocked
			action.Description = fmt.Sprintf(
				"APT repair for %s is blocked before execution.",
				profile.DisplayName,
			)
			action.Commands = nil
			action.RequiresConsent = false
			action.Eligible = false
			action.BlockReason = strings.TrimSpace(err.Error())
			actions = append(actions, action)
			continue
		}

		action.RenderedSource = renderedSource
		action.Description = fmt.Sprintf(
			"Restore the missing repository-scoped keyring for %s and rewrite only %s.",
			profile.DisplayName,
			profile.SourceFile,
		)
		action.Commands = []string{
			"Create a targeted APT source/keyring snapshot before mutation.",
			"Create /etc/apt/keyrings with mode 0755 if missing.",
			"Download the pinned key from: " + profile.KeyURL,
			"Verify the downloaded key against the profile's full GPG fingerprint list.",
			"Write keyring: " + profile.KeyringPath,
			"Write rendered source file: " + profile.SourceFile,
			"Rendered source: " + renderedSource,
			"Run apt-get update for final verification.",
		}

		actions = append(actions, action)
	}

	return actions
}
