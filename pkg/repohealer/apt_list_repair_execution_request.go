package repohealer

import (
	"fmt"
	"reflect"
)

const HashiCorpAPTListRepairConfirmation = "REPAIR HASHICORP"

type HashiCorpAPTListRepairExecutionRequest struct {
	ActionID            string
	ProfileID           string
	RepositoryURL       string
	SourceFile          string
	SourceLine          int
	KeyringPath         string
	KeyURL              string
	ExpectedFingerprint string
	PlannedWrites       []string
	VerificationSteps   []string
}

func BuildHashiCorpAPTListRepairExecutionRequest(
	preview APTListRepairPreview,
	confirmation string,
) (HashiCorpAPTListRepairExecutionRequest, error) {
	if !preview.Ready {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: preview is not ready",
		)
	}

	if confirmation != HashiCorpAPTListRepairConfirmation {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: exact confirmation %q is required",
			HashiCorpAPTListRepairConfirmation,
		)
	}

	if preview.ActionID != "apt-keyring-repair-hashicorp" {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: action %q is not approved",
			preview.ActionID,
		)
	}

	if preview.ProfileID != HashiCorpAPTListProfileID {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: profile %q is not %q",
			preview.ProfileID,
			HashiCorpAPTListProfileID,
		)
	}

	profile, ok := FindVendorProfileByID(
		ManagerAPT,
		HashiCorpAPTListProfileID,
	)
	if !ok {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: pinned profile is unavailable",
		)
	}

	if preview.RepositoryURL != HashiCorpAPTListRepositoryURL ||
		!profileAllowsExactRepositoryURL(profile, preview.RepositoryURL) {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: repository %q is not exact",
			preview.RepositoryURL,
		)
	}

	if preview.SourceFile != profile.SourceFile {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: source file %q is not approved",
			preview.SourceFile,
		)
	}

	if preview.SourceLine < 1 {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: source line %d is invalid",
			preview.SourceLine,
		)
	}

	if preview.KeyringPath != profile.KeyringPath {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: keyring path %q is not approved",
			preview.KeyringPath,
		)
	}

	if preview.KeyURL != profile.KeyURL {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: key URL %q is not approved",
			preview.KeyURL,
		)
	}

	if preview.ExpectedFingerprint != HashiCorpAPTListExpectedFingerprint ||
		!IsPinnedFingerprint(profile, preview.ExpectedFingerprint) {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: fingerprint %q is not pinned",
			preview.ExpectedFingerprint,
		)
	}

	expectedWrites := []string{
		fmt.Sprintf(
			"Install the verified %s signing key at %s as root-owned mode 0644 using an atomic replacement.",
			profile.DisplayName,
			profile.KeyringPath,
		),
	}
	if !reflect.DeepEqual(preview.PlannedWrites, expectedWrites) {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: planned writes do not match the approved plan",
		)
	}

	expectedVerification := []string{
		"Re-run the read-only APT-list Doctor.",
		"Run apt-get update.",
	}
	if !reflect.DeepEqual(preview.VerificationSteps, expectedVerification) {
		return HashiCorpAPTListRepairExecutionRequest{}, fmt.Errorf(
			"HashiCorp APT-list repair request blocked: verification steps do not match the approved plan",
		)
	}

	return HashiCorpAPTListRepairExecutionRequest{
		ActionID:            preview.ActionID,
		ProfileID:           profile.ID,
		RepositoryURL:       preview.RepositoryURL,
		SourceFile:          preview.SourceFile,
		SourceLine:          preview.SourceLine,
		KeyringPath:         profile.KeyringPath,
		KeyURL:              profile.KeyURL,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		PlannedWrites:       append([]string(nil), expectedWrites...),
		VerificationSteps:   append([]string(nil), expectedVerification...),
	}, nil
}
