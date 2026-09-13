package repohealer

import (
	"fmt"
	"strings"
)

type APTListDoctorServiceResult struct {
	Report   APTListDoctorReport
	JSON     []byte
	ExitCode int
}

func RunSelectedAPTListDoctorRemoteService(
	exec Executor,
	facts TargetFacts,
	action RepairAction,
) (APTListDoctorServiceResult, error) {
	probe, err := ProbeSelectedAPTListRepairMetadata(exec, action)
	if err != nil {
		report := unknownAPTListDoctorReport(
			facts,
			action,
			"remote_probe",
			fmt.Sprintf(
				"Remote APT list Doctor metadata probe could not complete: %v",
				err,
			),
		)
		return buildAPTListDoctorServiceResult(report)
	}

	report := DiagnoseSelectedAPTListRepairRemoteReadiness(
		facts,
		action,
		probe,
	)

	return buildAPTListDoctorServiceResult(report)
}

func DiagnoseSelectedAPTListRepairRemoteReadiness(
	facts TargetFacts,
	action RepairAction,
	probe APTListDoctorRemoteProbe,
) APTListDoctorReport {
	report := APTListDoctorReport{
		Overall:             APTListDoctorStatusReady,
		Target:              facts,
		ActionID:            action.ID,
		ProfileID:           action.ProfileID,
		RepositoryURL:       action.RepositoryURL,
		SourceFile:          action.SourceFile,
		SourceLine:          action.SourceLine,
		KeyringPath:         action.KeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
	}

	if err := validateAPTListDoctorProbeAction(action); err != nil {
		return blockedAPTListDoctorReport(
			facts,
			action,
			"action_binding",
			fmt.Sprintf("Selected APT list action is not safe to inspect: %v", err),
		)
	}

	if facts.Platform != PlatformLinux ||
		facts.PackageManager != ManagerAPT {
		return unsupportedAPTListDoctorReport(
			facts,
			action,
			"target_platform",
			"APT list Doctor requires a Linux target using APT.",
		)
	}

	if !probe.APTAvailable {
		return blockedAPTListDoctorReport(
			facts,
			action,
			"remote_apt_get",
			"Remote target does not provide apt-get.",
		)
	}

	if !probe.GPGAvailable {
		return blockedAPTListDoctorReport(
			facts,
			action,
			"remote_gpg",
			"Remote target does not provide gpg for keyring metadata inspection.",
		)
	}

	if check, blocked := aptListDoctorRemoteFileCheck(
		"remote_source_file",
		"source",
		probe.Source,
	); blocked {
		return blockedAPTListDoctorReportWithCheck(
			report,
			check,
		)
	} else {
		report.Checks = append(report.Checks, check)
	}

	if check, blocked := aptListDoctorRemoteFileCheck(
		"remote_keyring_file",
		"keyring",
		probe.Keyring,
	); blocked {
		return blockedAPTListDoctorReportWithCheck(
			report,
			check,
		)
	} else {
		report.Checks = append(report.Checks, check)
	}

	report.Checks = append(
		report.Checks,
		APTListDoctorCheck{
			Name:    "remote_apt_get",
			Status:  APTListDoctorStatusReady,
			Message: "Remote target provides apt-get.",
		},
		APTListDoctorCheck{
			Name:    "remote_gpg",
			Status:  APTListDoctorStatusReady,
			Message: "Remote target provides gpg.",
		},
	)

	if !containsAPTListDoctorFingerprint(
		probe.KeyringFingerprints,
		HashiCorpAPTListExpectedFingerprint,
	) {
		return blockedAPTListDoctorReportWithCheck(
			report,
			APTListDoctorCheck{
				Name:   "expected_signing_key",
				Status: APTListDoctorStatusBlocked,
				Message: "The expected HashiCorp signing fingerprint " +
					HashiCorpAPTListExpectedFingerprint +
					" is absent from the pinned keyring.",
			},
		)
	}

	report.Checks = append(
		report.Checks,
		APTListDoctorCheck{
			Name:    "expected_signing_key",
			Status:  APTListDoctorStatusReady,
			Message: "The expected HashiCorp signing fingerprint is present in the pinned keyring.",
		},
	)

	return report
}

func buildAPTListDoctorServiceResult(
	report APTListDoctorReport,
) (APTListDoctorServiceResult, error) {
	encoded, err := MarshalAPTListDoctorReportJSON(report)
	if err != nil {
		return APTListDoctorServiceResult{
			Report:   report,
			ExitCode: APTListDoctorExitUnknown,
		}, fmt.Errorf("marshal APT list Doctor service report: %w", err)
	}

	return APTListDoctorServiceResult{
		Report:   report,
		JSON:     encoded,
		ExitCode: APTListDoctorExitCode(report.Overall),
	}, nil
}

func blockedAPTListDoctorReport(
	facts TargetFacts,
	action RepairAction,
	checkName string,
	message string,
) APTListDoctorReport {
	return APTListDoctorReport{
		Overall:             APTListDoctorStatusBlocked,
		Target:              facts,
		ActionID:            action.ID,
		ProfileID:           action.ProfileID,
		RepositoryURL:       action.RepositoryURL,
		SourceFile:          action.SourceFile,
		SourceLine:          action.SourceLine,
		KeyringPath:         action.KeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		Checks: []APTListDoctorCheck{
			{
				Name:    checkName,
				Status:  APTListDoctorStatusBlocked,
				Message: message,
			},
		},
	}
}

func unsupportedAPTListDoctorReport(
	facts TargetFacts,
	action RepairAction,
	checkName string,
	message string,
) APTListDoctorReport {
	return APTListDoctorReport{
		Overall:             APTListDoctorStatusUnsupported,
		Target:              facts,
		ActionID:            action.ID,
		ProfileID:           action.ProfileID,
		RepositoryURL:       action.RepositoryURL,
		SourceFile:          action.SourceFile,
		SourceLine:          action.SourceLine,
		KeyringPath:         action.KeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		Checks: []APTListDoctorCheck{
			{
				Name:    checkName,
				Status:  APTListDoctorStatusUnsupported,
				Message: message,
			},
		},
	}
}

func unknownAPTListDoctorReport(
	facts TargetFacts,
	action RepairAction,
	checkName string,
	message string,
) APTListDoctorReport {
	return APTListDoctorReport{
		Overall:             APTListDoctorStatusUnknown,
		Target:              facts,
		ActionID:            action.ID,
		ProfileID:           action.ProfileID,
		RepositoryURL:       action.RepositoryURL,
		SourceFile:          action.SourceFile,
		SourceLine:          action.SourceLine,
		KeyringPath:         action.KeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		Checks: []APTListDoctorCheck{
			{
				Name:    checkName,
				Status:  APTListDoctorStatusUnknown,
				Message: message,
			},
		},
	}
}

func blockedAPTListDoctorReportWithCheck(
	report APTListDoctorReport,
	check APTListDoctorCheck,
) APTListDoctorReport {
	report.Overall = APTListDoctorStatusBlocked
	report.CanInspect = false
	report.CanPreview = false
	report.CanApply = false
	report.Checks = append(report.Checks, check)

	return report
}

func aptListDoctorRemoteFileCheck(
	name string,
	kind string,
	file APTListDoctorRemoteFile,
) (APTListDoctorCheck, bool) {
	switch file.State {
	case APTListDoctorFileStatePresent:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusReady,
			Message: "Remote " + kind + " file is present and safely owned.",
		}, false
	case APTListDoctorFileStateMissing:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file is missing.",
		}, true
	case APTListDoctorFileStateSymlink:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file is a symlink.",
		}, true
	case APTListDoctorFileStateNotRegular:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " path is not a regular file.",
		}, true
	case APTListDoctorFileStateUnsafeOwner:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file ownership is unsafe.",
		}, true
	case APTListDoctorFileStateUnsafeMode:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file permissions are unsafe.",
		}, true
	case APTListDoctorFileStateUnreadable:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file is unreadable.",
		}, true
	default:
		return APTListDoctorCheck{
			Name:    name,
			Status:  APTListDoctorStatusBlocked,
			Message: "Remote " + kind + " file metadata is invalid.",
		}, true
	}
}

func containsAPTListDoctorFingerprint(
	fingerprints []string,
	expected string,
) bool {
	expected = strings.ToUpper(strings.TrimSpace(expected))

	for _, fingerprint := range fingerprints {
		if strings.ToUpper(strings.TrimSpace(fingerprint)) == expected {
			return true
		}
	}

	return false
}
