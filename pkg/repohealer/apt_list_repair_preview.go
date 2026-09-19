package repohealer

import (
	"fmt"
	"strings"
)

const APTListRepairPreviewSafetyNotice = "PREVIEW ONLY: no system changes were made."

type APTListRepairPreview struct {
	Ready               bool
	Reason              string
	ActionID            string
	ProfileID           string
	ProfileDisplayName  string
	RepositoryURL       string
	SourceFile          string
	SourceLine          int
	KeyringPath         string
	KeyURL              string
	ExpectedFingerprint string
	PlannedWrites       []string
	VerificationSteps   []string
	SafetyNotice        string
}

func PreviewBlockedHashiCorpAPTListRepair(
	report APTListDoctorReport,
) APTListRepairPreview {
	preview := APTListRepairPreview{
		ActionID:            report.ActionID,
		ProfileID:           report.ProfileID,
		RepositoryURL:       report.RepositoryURL,
		SourceFile:          report.SourceFile,
		SourceLine:          report.SourceLine,
		KeyringPath:         report.KeyringPath,
		ExpectedFingerprint: report.ExpectedFingerprint,
		SafetyNotice:        APTListRepairPreviewSafetyNotice,
	}

	profile, err := validatedHashiCorpAPTListPreviewProfile(report)
	if err != nil {
		preview.Reason = strings.TrimSpace(err.Error())
		return preview
	}

	preview.ProfileID = profile.ID
	preview.ProfileDisplayName = profile.DisplayName
	preview.KeyURL = profile.KeyURL
	preview.KeyringPath = profile.KeyringPath
	preview.ExpectedFingerprint = HashiCorpAPTListExpectedFingerprint
	preview.PlannedWrites = []string{
		fmt.Sprintf(
			"Install the verified %s signing key at %s as root-owned mode 0644 using an atomic replacement.",
			profile.DisplayName,
			profile.KeyringPath,
		),
	}
	preview.VerificationSteps = []string{
		"Re-run the read-only APT-list Doctor.",
		"Run apt-get update.",
	}
	preview.Ready = true

	return preview
}

func validatedHashiCorpAPTListPreviewProfile(
	report APTListDoctorReport,
) (VendorProfile, error) {
	if report.Overall != APTListDoctorStatusBlocked {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: Doctor report must be blocked",
		)
	}

	if report.CanInspect || report.CanPreview || report.CanApply {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: Doctor report must not permit inspection, preview, or apply",
		)
	}

	if report.Target.Platform != PlatformLinux ||
		report.Target.PackageManager != ManagerAPT {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: Doctor report must describe a Linux target using APT",
		)
	}

	if report.ActionID != "apt-keyring-repair-hashicorp" {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: action %q is not the HashiCorp APT-list Doctor action",
			report.ActionID,
		)
	}

	if report.ProfileID != HashiCorpAPTListProfileID {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: profile %q is not %q",
			report.ProfileID,
			HashiCorpAPTListProfileID,
		)
	}

	profile, ok := FindVendorProfileByID(
		ManagerAPT,
		HashiCorpAPTListProfileID,
	)
	if !ok {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: HashiCorp profile is unavailable",
		)
	}

	if report.RepositoryURL != HashiCorpAPTListRepositoryURL ||
		!profileAllowsExactRepositoryURL(profile, report.RepositoryURL) {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: repository %q is not the exact HashiCorp repository",
			report.RepositoryURL,
		)
	}

	if report.SourceFile != profile.SourceFile {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: source file %q does not match HashiCorp source file %q",
			report.SourceFile,
			profile.SourceFile,
		)
	}

	if report.SourceLine < 1 {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: source line %d is invalid",
			report.SourceLine,
		)
	}

	if report.KeyringPath != profile.KeyringPath {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: keyring path %q does not match HashiCorp keyring path %q",
			report.KeyringPath,
			profile.KeyringPath,
		)
	}

	if report.ExpectedFingerprint != HashiCorpAPTListExpectedFingerprint ||
		!IsPinnedFingerprint(profile, report.ExpectedFingerprint) {
		return VendorProfile{}, fmt.Errorf(
			"APT-list repair preview blocked: expected fingerprint %q does not match the pinned HashiCorp fingerprint",
			report.ExpectedFingerprint,
		)
	}

	for _, name := range []string{
		"remote_source_file",
		"remote_keyring_file",
		"remote_apt_get",
		"remote_gpg",
	} {
		if err := requireExactlyOneAPTListDoctorCheck(
			report.Checks,
			name,
			APTListDoctorStatusReady,
		); err != nil {
			return VendorProfile{}, err
		}
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		report.Checks,
		"expected_signing_key",
		APTListDoctorStatusBlocked,
	); err != nil {
		return VendorProfile{}, err
	}

	return profile, nil
}

func requireExactlyOneAPTListDoctorCheck(
	checks []APTListDoctorCheck,
	name string,
	want APTListDoctorStatus,
) error {
	count := 0
	var got APTListDoctorStatus

	for _, check := range checks {
		if check.Name != name {
			continue
		}

		count++
		got = check.Status
	}

	if count == 0 {
		return fmt.Errorf(
			"APT-list repair preview blocked: required Doctor check %q is missing",
			name,
		)
	}

	if count != 1 {
		return fmt.Errorf(
			"APT-list repair preview blocked: required Doctor check %q is ambiguous",
			name,
		)
	}

	if got != want {
		return fmt.Errorf(
			"APT-list repair preview blocked: required Doctor check %q has status %q, want %q",
			name,
			got,
			want,
		)
	}

	return nil
}
