package repohealer

import (
	"fmt"
	"path"
	"strings"
)

type PreparedDeb822Repair struct {
	ProfileID       string
	SourceFile      string
	KeyringPath     string
	RenderedSource  string
	SnapshotTargets []string
}

func PrepareDeb822Repair(
	action RepairAction,
	profile VendorProfile,
	document string,
) (PreparedDeb822Repair, error) {
	if err := validateDeb822RepairAction(action, profile); err != nil {
		return PreparedDeb822Repair{}, err
	}

	validation := ValidateSingleProfileDeb822Document(document, profile)
	if !validation.Valid {
		return PreparedDeb822Repair{}, fmt.Errorf(
			"Deb822 repair preparation blocked: %s",
			validation.Reason,
		)
	}

	renderedSource, err := RenderAPTDeb822Source(profile, SourceRenderInput{
		Architecture: action.Target.Architecture,
		Distribution: action.Target.Distribution,
		Version:      action.Target.Version,
		Codename:     action.Target.Codename,
	})
	if err != nil {
		return PreparedDeb822Repair{}, fmt.Errorf(
			"Deb822 repair preparation blocked: unable to render source for %s: %w",
			profile.DisplayName,
			err,
		)
	}

	return PreparedDeb822Repair{
		ProfileID:      profile.ID,
		SourceFile:     action.SourceFile,
		KeyringPath:    profile.KeyringPath,
		RenderedSource: renderedSource,
		SnapshotTargets: []string{
			action.SourceFile,
			profile.KeyringPath,
		},
	}, nil
}

func validateDeb822RepairAction(
	action RepairAction,
	profile VendorProfile,
) error {
	if profile.PackageManager != ManagerAPT {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: profile %q is not an APT profile",
			profile.ID,
		)
	}

	if !action.Eligible {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: action %q is not eligible",
			action.ID,
		)
	}

	if !action.RequiresConsent {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: action %q does not require explicit consent",
			action.ID,
		)
	}

	if action.SourceFormat != SourceFormatDeb822 {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: action source format %q is not Deb822",
			action.SourceFormat,
		)
	}

	if !IsKnownAPTRepairFinding(action.FindingCode) {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: action %q has unsupported APT finding code %q",
			action.ID,
			action.FindingCode,
		)
	}

	if action.ProfileID != profile.ID {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: action profile %q does not match verified profile %q",
			action.ProfileID,
			profile.ID,
		)
	}

	if action.RepositoryURL == "" ||
		!profileAllowsExactRepositoryURL(profile, action.RepositoryURL) {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved repository URL %q is not exact for profile %q",
			action.RepositoryURL,
			profile.ID,
		)
	}

	if action.KeyringPath != profile.KeyringPath {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved keyring path %q does not match verified profile keyring path %q",
			action.KeyringPath,
			profile.KeyringPath,
		)
	}

	if err := validateApprovedDeb822SourcePath(action.SourceFile); err != nil {
		return err
	}

	return nil
}

func validateApprovedDeb822SourcePath(sourceFile string) error {
	sourceFile = strings.TrimSpace(sourceFile)

	if sourceFile == "" {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved source file is empty",
		)
	}

	const sourceDirectory = "/etc/apt/sources.list.d"

	if path.Dir(sourceFile) != sourceDirectory {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved source file %q is outside %s",
			sourceFile,
			sourceDirectory,
		)
	}

	if !strings.HasSuffix(sourceFile, ".sources") {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved source file %q does not have a .sources suffix",
			sourceFile,
		)
	}

	if path.Base(sourceFile) == ".sources" {
		return fmt.Errorf(
			"Deb822 repair preparation blocked: approved source file %q has an empty basename",
			sourceFile,
		)
	}

	return nil
}
