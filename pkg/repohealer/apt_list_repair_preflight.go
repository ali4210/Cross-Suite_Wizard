package repohealer

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

type HashiCorpAPTListRepairPreflightFileState string

const (
	HashiCorpAPTListRepairPreflightFilePresent     HashiCorpAPTListRepairPreflightFileState = "present"
	HashiCorpAPTListRepairPreflightFileMissing     HashiCorpAPTListRepairPreflightFileState = "missing"
	HashiCorpAPTListRepairPreflightFileSymlink     HashiCorpAPTListRepairPreflightFileState = "symlink"
	HashiCorpAPTListRepairPreflightFileNotRegular  HashiCorpAPTListRepairPreflightFileState = "not_regular"
	HashiCorpAPTListRepairPreflightFileUnsafeOwner HashiCorpAPTListRepairPreflightFileState = "unsafe_owner"
	HashiCorpAPTListRepairPreflightFileUnsafeMode  HashiCorpAPTListRepairPreflightFileState = "unsafe_mode"
	HashiCorpAPTListRepairPreflightFileUnreadable  HashiCorpAPTListRepairPreflightFileState = "unreadable"
)

type HashiCorpAPTListRepairPreflightFile struct {
	State  HashiCorpAPTListRepairPreflightFileState
	UID    int
	Mode   string
	Size   int64
	SHA256 string
}

type HashiCorpAPTListRepairPreflightProbe struct {
	Source           HashiCorpAPTListRepairPreflightFile
	Keyring          HashiCorpAPTListRepairPreflightFile
	APTAvailable     bool
	GPGAvailable     bool
	InstallAvailable bool
	MVAvailable      bool
	SHA256Available  bool
	APTLockActive    bool
}

type HashiCorpAPTListRepairPreflight struct {
	Ready        bool
	Reason       string
	Request      HashiCorpAPTListRepairExecutionRequest
	Source       HashiCorpAPTListRepairPreflightFile
	Keyring      HashiCorpAPTListRepairPreflightFile
	DoctorReport APTListDoctorReport
}

var hashicorpAPTListRepairSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func EvaluateHashiCorpAPTListRepairPreflight(
	request HashiCorpAPTListRepairExecutionRequest,
	probe HashiCorpAPTListRepairPreflightProbe,
	report APTListDoctorReport,
) HashiCorpAPTListRepairPreflight {
	result := HashiCorpAPTListRepairPreflight{
		Request:      request,
		Source:       probe.Source,
		Keyring:      probe.Keyring,
		DoctorReport: report,
	}

	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		result.Reason = err.Error()
		return result
	}

	if err := validateHashiCorpAPTListRepairPreflightFile("source", probe.Source); err != nil {
		result.Reason = err.Error()
		return result
	}

	if err := validateHashiCorpAPTListRepairPreflightKeyring(probe.Keyring); err != nil {
		result.Reason = err.Error()
		return result
	}

	for _, tool := range []struct {
		name      string
		available bool
	}{
		{name: "apt-get", available: probe.APTAvailable},
		{name: "gpg", available: probe.GPGAvailable},
		{name: "install", available: probe.InstallAvailable},
		{name: "mv", available: probe.MVAvailable},
		{name: "sha256sum", available: probe.SHA256Available},
	} {
		if !tool.available {
			result.Reason = fmt.Sprintf(
				"HashiCorp APT-list repair preflight blocked: required tool %q is unavailable",
				tool.name,
			)
			return result
		}
	}

	if probe.APTLockActive {
		result.Reason = "HashiCorp APT-list repair preflight blocked: APT/dpkg lock is active"
		return result
	}

	if err := validateHashiCorpAPTListRepairDoctorBinding(
		request,
		probe.Keyring,
		report,
	); err != nil {
		result.Reason = err.Error()
		return result
	}

	result.Ready = true
	return result
}

func validateHashiCorpAPTListRepairExecutionRequest(
	request HashiCorpAPTListRepairExecutionRequest,
) error {
	preview := APTListRepairPreview{
		Ready:               true,
		ActionID:            request.ActionID,
		ProfileID:           request.ProfileID,
		RepositoryURL:       request.RepositoryURL,
		SourceFile:          request.SourceFile,
		SourceLine:          request.SourceLine,
		KeyringPath:         request.KeyringPath,
		KeyURL:              request.KeyURL,
		ExpectedFingerprint: request.ExpectedFingerprint,
		PlannedWrites:       append([]string(nil), request.PlannedWrites...),
		VerificationSteps:   append([]string(nil), request.VerificationSteps...),
	}

	canonical, err := BuildHashiCorpAPTListRepairExecutionRequest(
		preview,
		HashiCorpAPTListRepairConfirmation,
	)
	if err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: request is invalid: %w",
			err,
		)
	}

	if !reflect.DeepEqual(request, canonical) {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: request does not match the canonical approved binding",
		)
	}

	return nil
}

func validateHashiCorpAPTListRepairPreflightKeyring(
	keyring HashiCorpAPTListRepairPreflightFile,
) error {
	if keyring.State == HashiCorpAPTListRepairPreflightFileMissing {
		return nil
	}

	return validateHashiCorpAPTListRepairPreflightFile("keyring", keyring)
}

func validateHashiCorpAPTListRepairPreflightFile(
	kind string,
	file HashiCorpAPTListRepairPreflightFile,
) error {
	if file.State != HashiCorpAPTListRepairPreflightFilePresent {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %s file state %q is unsafe",
			kind,
			file.State,
		)
	}

	if file.UID != 0 {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %s file owner UID %d is unsafe",
			kind,
			file.UID,
		)
	}

	if file.Mode != "644" {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %s file mode %q is unsafe",
			kind,
			file.Mode,
		)
	}

	if file.Size < 1 {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %s file size %d is invalid",
			kind,
			file.Size,
		)
	}

	sha256 := strings.ToLower(strings.TrimSpace(file.SHA256))
	if !hashicorpAPTListRepairSHA256Pattern.MatchString(sha256) {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %s SHA-256 is invalid",
			kind,
		)
	}

	return nil
}

func validateHashiCorpAPTListRepairDoctorKeyringPairing(
	checks []APTListDoctorCheck,
	keyringState HashiCorpAPTListRepairPreflightFileState,
) error {
	want := APTListDoctorStatusReady
	if keyringState == HashiCorpAPTListRepairPreflightFileMissing {
		want = APTListDoctorStatusBlocked
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		checks,
		"remote_keyring_file",
		want,
	); err != nil {
		return fmt.Errorf(
			"Doctor keyring state %q does not match preflight keyring state: %w",
			keyringState,
			err,
		)
	}

	return nil
}

func validateHashiCorpAPTListRepairDoctorBinding(
	request HashiCorpAPTListRepairExecutionRequest,
	keyring HashiCorpAPTListRepairPreflightFile,
	report APTListDoctorReport,
) error {
	if report.Overall != APTListDoctorStatusBlocked {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor report must be blocked",
		)
	}

	if report.CanInspect || report.CanPreview || report.CanApply {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor report must not permit inspection, preview, or apply",
		)
	}

	if report.Target.Platform != PlatformLinux ||
		report.Target.PackageManager != ManagerAPT {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor target is not Linux using APT",
		)
	}

	if report.ActionID != request.ActionID {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor action %q does not match request action %q",
			report.ActionID,
			request.ActionID,
		)
	}

	if report.ProfileID != request.ProfileID {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor profile %q does not match request profile %q",
			report.ProfileID,
			request.ProfileID,
		)
	}

	if report.RepositoryURL != request.RepositoryURL {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor repository %q does not match request repository %q",
			report.RepositoryURL,
			request.RepositoryURL,
		)
	}

	if report.SourceFile != request.SourceFile ||
		report.SourceLine != request.SourceLine {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor source binding does not match request",
		)
	}

	if report.KeyringPath != request.KeyringPath {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor keyring %q does not match request keyring %q",
			report.KeyringPath,
			request.KeyringPath,
		)
	}

	if report.ExpectedFingerprint != request.ExpectedFingerprint {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: Doctor fingerprint %q does not match request fingerprint %q",
			report.ExpectedFingerprint,
			request.ExpectedFingerprint,
		)
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		report.Checks,
		"remote_source_file",
		APTListDoctorStatusReady,
	); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %w",
			err,
		)
	}

	if err := validateHashiCorpAPTListRepairDoctorKeyringPairing(
		report.Checks,
		keyring.State,
	); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %w",
			err,
		)
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		report.Checks,
		"remote_apt_get",
		APTListDoctorStatusReady,
	); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %w",
			err,
		)
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		report.Checks,
		"remote_gpg",
		APTListDoctorStatusReady,
	); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %w",
			err,
		)
	}

	if err := requireExactlyOneAPTListDoctorCheck(
		report.Checks,
		"expected_signing_key",
		APTListDoctorStatusBlocked,
	); err != nil {
		return fmt.Errorf(
			"HashiCorp APT-list repair preflight blocked: %w",
			err,
		)
	}

	return nil
}
