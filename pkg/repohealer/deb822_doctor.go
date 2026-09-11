package repohealer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Deb822DoctorStatus string

const (
	Deb822DoctorStatusReady       Deb822DoctorStatus = "READY"
	Deb822DoctorStatusWarning     Deb822DoctorStatus = "WARNING"
	Deb822DoctorStatusBlocked     Deb822DoctorStatus = "BLOCKED"
	Deb822DoctorStatusUnsupported Deb822DoctorStatus = "UNSUPPORTED"
)

type Deb822DoctorCheck struct {
	Name    string             `json:"name"`
	Status  Deb822DoctorStatus `json:"status"`
	Message string             `json:"message"`
}

type Deb822DoctorReport struct {
	Overall    Deb822DoctorStatus  `json:"overall"`
	Target     TargetFacts         `json:"target"`
	ProfileID  string              `json:"profile_id,omitempty"`
	AuditPath  string              `json:"audit_path"`
	Checks     []Deb822DoctorCheck `json:"checks"`
	CanPreview bool                `json:"can_preview"`
	CanApply   bool                `json:"can_apply"`
}

func DiagnoseDeb822RepairReadiness(
	facts TargetFacts,
	profileID string,
) Deb822DoctorReport {
	report := Deb822DoctorReport{
		Overall:   Deb822DoctorStatusReady,
		Target:    facts,
		ProfileID: strings.TrimSpace(profileID),
		AuditPath: Deb822RepairAuditPath(),
	}

	add := func(
		name string,
		status Deb822DoctorStatus,
		message string,
	) {
		report.Checks = append(report.Checks, Deb822DoctorCheck{
			Name:    name,
			Status:  status,
			Message: message,
		})
		report.Overall = stricterDeb822DoctorStatus(report.Overall, status)
	}

	if facts.Platform != PlatformLinux {
		add(
			"platform",
			Deb822DoctorStatusUnsupported,
			fmt.Sprintf("Deb822 APT repair is supported only on Linux; target platform is %q.", facts.Platform),
		)
	} else {
		add("platform", Deb822DoctorStatusReady, "Linux target detected.")
	}

	if facts.PackageManager != ManagerAPT {
		add(
			"package_manager",
			Deb822DoctorStatusUnsupported,
			fmt.Sprintf("Deb822 repair requires APT; target package manager is %q.", facts.PackageManager),
		)
	} else {
		add("package_manager", Deb822DoctorStatusReady, "APT target detected.")
	}

	profile, profileFound := FindVendorProfileByID(ManagerAPT, report.ProfileID)
	if report.ProfileID == "" {
		add(
			"vendor_profile",
			Deb822DoctorStatusWarning,
			"No Deb822 vendor profile was selected; only general readiness is available.",
		)
	} else if !profileFound {
		add(
			"vendor_profile",
			Deb822DoctorStatusUnsupported,
			fmt.Sprintf("Deb822 vendor profile %q is not supported.", report.ProfileID),
		)
	} else {
		add(
			"vendor_profile",
			Deb822DoctorStatusReady,
			fmt.Sprintf("Verified APT vendor profile %q is available.", profile.DisplayName),
		)

		add(
			"source_path",
			Deb822DoctorStatusWarning,
			"Exact Deb822 source path is validated after a supported detected repair action is selected.",
		)

		if strings.TrimSpace(profile.KeyringPath) == "" {
			add(
				"keyring_path",
				Deb822DoctorStatusWarning,
				"Verified profile does not define a keyring path.",
			)
		} else {
			add(
				"keyring_path",
				Deb822DoctorStatusReady,
				fmt.Sprintf("Verified keyring path is configured: %s.", profile.KeyringPath),
			)
		}
	}

	if Deb822RepairExecutionEnabled() {
		add(
			"execution_policy",
			Deb822DoctorStatusReady,
			"Deb822 repair execution policy is enabled for this local process.",
		)
	} else {
		add(
			"execution_policy",
			Deb822DoctorStatusWarning,
			"Deb822 repair execution policy is disabled; preview remains available but apply requires CROSS_SUITE_DEB822_REPAIR_ENABLED=true.",
		)
	}

	if err := checkDeb822AuditPathWritable(report.AuditPath); err != nil {
		add(
			"audit_path",
			Deb822DoctorStatusWarning,
			fmt.Sprintf("Local audit path is not currently writable: %v", err),
		)
	} else {
		add(
			"audit_path",
			Deb822DoctorStatusReady,
			fmt.Sprintf("Local audit path is writable: %s.", report.AuditPath),
		)
	}

	report.CanPreview = report.Overall == Deb822DoctorStatusReady ||
		report.Overall == Deb822DoctorStatusWarning

	report.CanApply = report.CanPreview &&
		Deb822RepairExecutionEnabled() &&
		profileFound

	return report
}

func DiagnoseSelectedDeb822RepairReadiness(
	facts TargetFacts,
	action RepairAction,
) Deb822DoctorReport {
	report := DiagnoseDeb822RepairReadiness(facts, action.ProfileID)
	report.Checks = removeDeb822DoctorCheck(report.Checks, "source_path")
	report.Overall = deriveDeb822DoctorOverall(report.Checks)

	add := func(
		name string,
		status Deb822DoctorStatus,
		message string,
	) {
		report.Checks = append(report.Checks, Deb822DoctorCheck{
			Name:    name,
			Status:  status,
			Message: message,
		})
		report.Overall = stricterDeb822DoctorStatus(report.Overall, status)
	}

	if action.SourceFormat != SourceFormatDeb822 {
		add(
			"action_source_format",
			Deb822DoctorStatusUnsupported,
			fmt.Sprintf(
				"Selected action source format %q is not Deb822.",
				action.SourceFormat,
			),
		)
	} else {
		add(
			"action_source_format",
			Deb822DoctorStatusReady,
			"Selected action uses Deb822 source format.",
		)
	}

	if strings.TrimSpace(action.ID) == "" ||
		strings.TrimSpace(action.FindingCode) == "" ||
		strings.TrimSpace(action.ProfileID) == "" ||
		strings.TrimSpace(action.RepositoryURL) == "" ||
		strings.TrimSpace(action.SourceFile) == "" ||
		strings.TrimSpace(action.KeyringPath) == "" {
		add(
			"action_binding",
			Deb822DoctorStatusBlocked,
			"Selected Deb822 action binding is incomplete.",
		)
	} else {
		add(
			"action_binding",
			Deb822DoctorStatusReady,
			"Selected Deb822 action binding is complete.",
		)
	}

	profile, profileFound := FindVendorProfileByID(
		ManagerAPT,
		action.ProfileID,
	)
	if !profileFound {
		add(
			"action_profile",
			Deb822DoctorStatusUnsupported,
			fmt.Sprintf(
				"Selected action profile %q is not a supported APT profile.",
				action.ProfileID,
			),
		)
	} else {
		if action.KeyringPath != profile.KeyringPath {
			add(
				"action_keyring_binding",
				Deb822DoctorStatusBlocked,
				"Selected action keyring does not match its verified vendor profile.",
			)
		} else {
			add(
				"action_keyring_binding",
				Deb822DoctorStatusReady,
				"Selected action keyring matches its verified vendor profile.",
			)
		}

		if !profileAllowsExactRepositoryURL(profile, action.RepositoryURL) {
			add(
				"action_repository_binding",
				Deb822DoctorStatusBlocked,
				"Selected action repository URL does not match its verified vendor profile.",
			)
		} else {
			add(
				"action_repository_binding",
				Deb822DoctorStatusReady,
				"Selected action repository URL matches its verified vendor profile.",
			)
		}
	}

	if err := validateApprovedDeb822SourcePath(action.SourceFile); err != nil {
		add(
			"action_source_path",
			Deb822DoctorStatusBlocked,
			fmt.Sprintf("Selected Deb822 source path is unsafe: %v", err),
		)
	} else {
		add(
			"action_source_path",
			Deb822DoctorStatusReady,
			fmt.Sprintf(
				"Selected Deb822 source path is in approved scope: %s.",
				action.SourceFile,
			),
		)
	}

	if facts != action.Target {
		add(
			"action_target_binding",
			Deb822DoctorStatusBlocked,
			"Selected action target facts do not match the Doctor target facts.",
		)
	} else {
		add(
			"action_target_binding",
			Deb822DoctorStatusReady,
			"Selected action target facts match the Doctor target facts.",
		)
	}

	report.CanPreview = report.Overall == Deb822DoctorStatusReady ||
		report.Overall == Deb822DoctorStatusWarning
	report.CanApply = report.CanPreview &&
		Deb822RepairExecutionEnabled() &&
		profileFound

	return report
}

func removeDeb822DoctorCheck(
	checks []Deb822DoctorCheck,
	name string,
) []Deb822DoctorCheck {
	filtered := make([]Deb822DoctorCheck, 0, len(checks))

	for _, check := range checks {
		if check.Name == name {
			continue
		}
		filtered = append(filtered, check)
	}

	return filtered
}

func deriveDeb822DoctorOverall(
	checks []Deb822DoctorCheck,
) Deb822DoctorStatus {
	overall := Deb822DoctorStatusReady

	for _, check := range checks {
		overall = stricterDeb822DoctorStatus(overall, check.Status)
	}

	return overall
}

func FindVendorProfileByID(
	manager PackageManager,
	profileID string,
) (VendorProfile, bool) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return VendorProfile{}, false
	}

	for _, profile := range KnownVendorProfiles() {
		if profile.PackageManager == manager && profile.ID == profileID {
			return profile, true
		}
	}

	return VendorProfile{}, false
}

func stricterDeb822DoctorStatus(
	current Deb822DoctorStatus,
	candidate Deb822DoctorStatus,
) Deb822DoctorStatus {
	weight := map[Deb822DoctorStatus]int{
		Deb822DoctorStatusReady:       0,
		Deb822DoctorStatusWarning:     1,
		Deb822DoctorStatusUnsupported: 2,
		Deb822DoctorStatusBlocked:     3,
	}

	if weight[candidate] > weight[current] {
		return candidate
	}

	return current
}

func checkDeb822AuditPathWritable(auditPath string) error {
	auditPath = strings.TrimSpace(auditPath)
	if auditPath == "" {
		return fmt.Errorf("audit path is empty")
	}

	parent := filepath.Dir(auditPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create audit directory %q: %w", parent, err)
	}

	testFile, err := os.CreateTemp(parent, ".repohealer-audit-write-check-*")
	if err != nil {
		return fmt.Errorf("create temporary audit write check in %q: %w", parent, err)
	}

	name := testFile.Name()
	if err := testFile.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close temporary audit write check: %w", err)
	}

	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove temporary audit write check: %w", err)
	}

	return nil
}
