package repohealer

import (
	"fmt"
	"strings"
)

type Deb822RepairExecutionRequest struct {
	ActionID             string
	FindingCode          string
	ProfileID            string
	ProfileDisplayName   string
	RepositoryURL        string
	SourceFile           string
	SourceFormat         SourceFormat
	KeyringPath          string
	RenderedSource       string
	SnapshotTargets      []string
	Target               TargetFacts
	ExpectedFingerprints []string
}

func BuildDeb822RepairExecutionRequest(
	inspection Deb822RepairInspection,
	action RepairAction,
	profile VendorProfile,
) (Deb822RepairExecutionRequest, error) {
	if !inspection.Ready {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection is not ready: %s",
			strings.TrimSpace(inspection.BlockReason),
		)
	}

	if action.SourceFormat != SourceFormatDeb822 {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: action source format %q is not Deb822",
			action.SourceFormat,
		)
	}

	if action.Eligible || action.RequiresConsent {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection source action must remain blocked and non-consent-bearing",
		)
	}

	if action.ID == "" ||
		action.FindingCode == "" ||
		action.ProfileID == "" ||
		action.RepositoryURL == "" ||
		action.SourceFile == "" ||
		action.KeyringPath == "" {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: action binding is incomplete",
		)
	}

	if profile.PackageManager != ManagerAPT {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: profile %q is not an APT profile",
			profile.ID,
		)
	}

	if profile.ID != action.ProfileID {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: action profile %q does not match verified profile %q",
			action.ProfileID,
			profile.ID,
		)
	}

	if action.KeyringPath != profile.KeyringPath {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: action keyring path %q does not match verified profile keyring path %q",
			action.KeyringPath,
			profile.KeyringPath,
		)
	}

	if !profileAllowsExactRepositoryURL(profile, action.RepositoryURL) {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: action repository URL %q is not exact for profile %q",
			action.RepositoryURL,
			profile.ID,
		)
	}

	if err := validateApprovedDeb822SourcePath(action.SourceFile); err != nil {
		return Deb822RepairExecutionRequest{}, err
	}

	if inspection.ActionID != action.ID ||
		inspection.ProfileID != profile.ID ||
		inspection.ProfileName != profile.DisplayName ||
		inspection.SourceFile != action.SourceFile ||
		inspection.KeyringPath != profile.KeyringPath {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection does not match the approved action and profile",
		)
	}

	if strings.TrimSpace(inspection.RenderedSource) == "" {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection has no rendered replacement source",
		)
	}

	validation := ValidateSingleProfileDeb822Document(
		inspection.RenderedSource,
		profile,
	)
	if !validation.Valid {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection rendered replacement source is invalid: %s",
			validation.Reason,
		)
	}

	expectedTargets := []string{
		action.SourceFile,
		profile.KeyringPath,
	}
	if !sameOrderedStrings(inspection.SnapshotTargets, expectedTargets) {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: inspection snapshot targets do not match approved repair scope",
		)
	}

	if len(profile.ExpectedFingerprints) == 0 {
		return Deb822RepairExecutionRequest{}, fmt.Errorf(
			"Deb822 execution request blocked: profile %q has no pinned signing-key fingerprints",
			profile.ID,
		)
	}

	return Deb822RepairExecutionRequest{
		ActionID:             action.ID,
		FindingCode:          action.FindingCode,
		ProfileID:            profile.ID,
		ProfileDisplayName:   profile.DisplayName,
		RepositoryURL:        action.RepositoryURL,
		SourceFile:           action.SourceFile,
		SourceFormat:         action.SourceFormat,
		KeyringPath:          profile.KeyringPath,
		RenderedSource:       inspection.RenderedSource,
		SnapshotTargets:      append([]string(nil), expectedTargets...),
		Target:               action.Target,
		ExpectedFingerprints: append([]string(nil), profile.ExpectedFingerprints...),
	}, nil
}

func sameOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}
