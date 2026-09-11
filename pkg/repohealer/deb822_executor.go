package repohealer

import (
	"fmt"
	"strings"
)

type Deb822RepairExecutionStatus string

const (
	Deb822RepairExecutionStatusBlocked Deb822RepairExecutionStatus = "blocked"
	Deb822RepairExecutionStatusReady   Deb822RepairExecutionStatus = "ready"
)

type Deb822RepairExecutionResult struct {
	Status      Deb822RepairExecutionStatus
	ActionID    string
	ProfileID   string
	SourceFile  string
	KeyringPath string
	Reason      string
}

func ValidateDeb822RepairExecutionRequest(
	request Deb822RepairExecutionRequest,
) error {
	if strings.TrimSpace(request.ActionID) == "" ||
		strings.TrimSpace(request.FindingCode) == "" ||
		strings.TrimSpace(request.ProfileID) == "" ||
		strings.TrimSpace(request.ProfileDisplayName) == "" ||
		strings.TrimSpace(request.RepositoryURL) == "" ||
		strings.TrimSpace(request.SourceFile) == "" ||
		strings.TrimSpace(request.KeyringPath) == "" {
		return fmt.Errorf("Deb822 execution request blocked: request binding is incomplete")
	}

	if request.SourceFormat != SourceFormatDeb822 {
		return fmt.Errorf(
			"Deb822 execution request blocked: request source format %q is not Deb822",
			request.SourceFormat,
		)
	}

	profile, ok := FindVendorProfile(ManagerAPT, request.RepositoryURL)
	if !ok {
		return fmt.Errorf(
			"Deb822 execution request blocked: no verified APT profile matches repository URL %q",
			request.RepositoryURL,
		)
	}

	if request.ProfileID != profile.ID {
		return fmt.Errorf(
			"Deb822 execution request blocked: request profile %q does not match verified profile %q",
			request.ProfileID,
			profile.ID,
		)
	}

	if profile.PackageManager != ManagerAPT {
		return fmt.Errorf(
			"Deb822 execution request blocked: profile %q is not an APT profile",
			profile.ID,
		)
	}

	if request.ProfileDisplayName != profile.DisplayName {
		return fmt.Errorf(
			"Deb822 execution request blocked: request profile display name %q does not match verified profile %q",
			request.ProfileDisplayName,
			profile.DisplayName,
		)
	}

	if request.KeyringPath != profile.KeyringPath {
		return fmt.Errorf(
			"Deb822 execution request blocked: request keyring path %q does not match verified profile keyring path %q",
			request.KeyringPath,
			profile.KeyringPath,
		)
	}

	if !profileAllowsExactRepositoryURL(profile, request.RepositoryURL) {
		return fmt.Errorf(
			"Deb822 execution request blocked: request repository URL %q is not exact for profile %q",
			request.RepositoryURL,
			profile.ID,
		)
	}

	if err := validateApprovedDeb822SourcePath(request.SourceFile); err != nil {
		return err
	}

	if strings.TrimSpace(request.RenderedSource) == "" {
		return fmt.Errorf(
			"Deb822 execution request blocked: request has no rendered replacement source",
		)
	}

	validation := ValidateSingleProfileDeb822Document(
		request.RenderedSource,
		profile,
	)
	if !validation.Valid {
		return fmt.Errorf(
			"Deb822 execution request blocked: rendered replacement source is invalid: %s",
			validation.Reason,
		)
	}

	expectedTargets := []string{
		request.SourceFile,
		profile.KeyringPath,
	}
	if !sameOrderedStrings(request.SnapshotTargets, expectedTargets) {
		return fmt.Errorf(
			"Deb822 execution request blocked: request snapshot targets do not match approved repair scope",
		)
	}

	if len(request.ExpectedFingerprints) == 0 {
		return fmt.Errorf(
			"Deb822 execution request blocked: request has no pinned signing-key fingerprints",
		)
	}

	if !sameOrderedStrings(
		request.ExpectedFingerprints,
		profile.ExpectedFingerprints,
	) {
		return fmt.Errorf(
			"Deb822 execution request blocked: request fingerprints do not match verified profile fingerprints",
		)
	}

	return nil
}

func PrepareDeb822RepairExecution(
	request Deb822RepairExecutionRequest,
) Deb822RepairExecutionResult {
	result := Deb822RepairExecutionResult{
		Status:      Deb822RepairExecutionStatusBlocked,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		SourceFile:  request.SourceFile,
		KeyringPath: request.KeyringPath,
	}

	if err := ValidateDeb822RepairExecutionRequest(request); err != nil {
		result.Reason = err.Error()
		return result
	}

	result.Status = Deb822RepairExecutionStatusReady
	result.Reason = ""
	return result
}
