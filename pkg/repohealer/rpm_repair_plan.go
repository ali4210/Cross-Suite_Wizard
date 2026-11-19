package repohealer

import "fmt"

// BuildRPMRepairPlan mirrors BuildRepairPlan (plan.go) for the dnf/yum/zypper family: it
// is the "preview" stage — for every known-vendor RPM finding, it renders exactly what
// repair would do (including the full .repo file content) without changing anything.
func BuildRPMRepairPlan(result Result) []RepairAction {
	actions := make([]RepairAction, 0)
	seenProfiles := make(map[string]bool)

	for _, finding := range result.Findings {
		if !IsKnownRPMRepairFinding(finding.Code) {
			continue
		}

		manager := canonicalRPMManager(result.Target.PackageManager)
		profile, ok := FindVendorProfile(manager, finding.RepositoryURL)
		if !ok || seenProfiles[profile.ID] {
			continue
		}
		seenProfiles[profile.ID] = true

		action := RepairAction{
			ID:                   RPMRepairActionID(profile.ID, finding.Code),
			FindingCode:          finding.Code,
			Risk:                 RiskKnownVendor,
			Description:          fmt.Sprintf("Prepare a repository-scoped RPM trust repair plan for %s.", profile.DisplayName),
			Commands:             []string{},
			Verification:         []string{RPMVerificationScript(profile.PackageManager)},
			Rollback:             []string{"Remove only the GPG key this repair newly imported, then restore the profile repo file and verified-key copy from the pre-repair snapshot."},
			RequiresConsent:      true,
			Eligible:             true,
			ProfileID:            profile.ID,
			ProfileDisplayName:   profile.DisplayName,
			RepositoryURL:        finding.RepositoryURL,
			Target:               result.Target,
			KeyURL:               profile.KeyURL,
			ExpectedFingerprints: append([]string(nil), profile.ExpectedFingerprints...),
			KeyringPath:          profile.KeyringPath,
			SourceFile:           profile.RPMRepoFile,
			SourceLine:           finding.SourceLine,
			SourceFormat:         finding.SourceFormat,
			SnapshotTargets: []string{
				profile.RPMRepoFile,
				profile.KeyringPath,
			},
		}

		if !RPMRepairExecutionEnabled() {
			action.Risk = RiskBlocked
			action.Description = fmt.Sprintf(
				"RPM repair for %s is blocked: the operator-policy environment variable %s is not set to \"true\" on this host.",
				profile.DisplayName,
				RPMRepairExecutionEnabledEnv,
			)
			action.RequiresConsent = false
			action.Eligible = false
			action.BlockReason = fmt.Sprintf(
				"Set %s=true before this repair can be approved and applied.",
				RPMRepairExecutionEnabledEnv,
			)
			actions = append(actions, action)
			continue
		}

		renderedSource, err := RenderRPMRepoFile(profile)
		if err != nil {
			action.Risk = RiskBlocked
			action.Description = fmt.Sprintf("RPM repair for %s is blocked before execution.", profile.DisplayName)
			action.RequiresConsent = false
			action.Eligible = false
			action.BlockReason = err.Error()
			actions = append(actions, action)
			continue
		}

		action.RenderedSource = renderedSource
		action.Description = fmt.Sprintf(
			"Re-verify %s's pinned signing key by fingerprint, import it into the RPM database, and rewrite only %s.",
			profile.DisplayName,
			profile.RPMRepoFile,
		)
		action.Commands = []string{
			"Create a targeted RPM repo-file/key snapshot before mutation.",
			"Record the set of already-imported GPG key NEVRAs (for a scoped rollback).",
			"Download the pinned key from: " + profile.KeyURL,
			"Verify the downloaded key against the profile's full GPG fingerprint list.",
			"Only after a fingerprint match: rpm --import the key.",
			"Write local verified-key copy: " + profile.KeyringPath,
			"Write rendered repo file: " + profile.RPMRepoFile,
			"Rendered repo file:\n" + renderedSource,
			"Run " + RPMVerificationScript(profile.PackageManager) + " for final verification.",
		}

		actions = append(actions, action)
	}

	return actions
}
