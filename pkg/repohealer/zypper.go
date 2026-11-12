package repohealer

import (
	"strings"
	"time"
)

// ZypperAdapter diagnoses and repairs the most common openSUSE zypper failures: a stale
// process lock, GPG signature problems, unreachable repositories, and stale/corrupted
// metadata.
type ZypperAdapter struct{}

func (ZypperAdapter) Manager() PackageManager { return ManagerZypper }

func (ZypperAdapter) Diagnose(
	exec Executor,
	facts TargetFacts,
	policy Policy,
) ([]CommandEvidence, []Finding, []RepairAction) {
	var evidence []CommandEvidence
	var findings []Finding
	var actions []RepairAction

	runSudo := func(command string) string {
		started := time.Now()
		output, err := exec.RunSudo(command)
		exitCode := 0
		if err != nil {
			exitCode = 1
		}
		evidence = append(evidence, CommandEvidence{
			Command:  command,
			Output:   strings.TrimSpace(output),
			ExitCode: exitCode,
			Duration: time.Since(started),
		})
		return output
	}

	lockState := runSudo(`
set +e
[ -f /var/run/zypp.pid ] && echo LOCK_PRESENT || echo LOCK_ABSENT
pgrep -x zypper >/dev/null 2>&1 && echo ZYPPER_RUNNING || echo ZYPPER_NOT_RUNNING
`)

	refresh := runSudo(`set +e
zypper --non-interactive refresh 2>&1
`)
	lower := strings.ToLower(refresh)

	if strings.Contains(lockState, "LOCK_PRESENT") && strings.Contains(lockState, "ZYPPER_NOT_RUNNING") {
		action := RepairAction{
			ID:              "zypper-remove-stale-lock",
			FindingCode:     "ZYPPER_LOCK_STALE",
			Risk:            RiskAutoSafe,
			Description:     "Remove zypper's stale process lock file.",
			Commands:        []string{"rm -f /var/run/zypp.pid"},
			Verification:    []string{"zypper --non-interactive refresh"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "/var/run/zypp.pid exists but no zypper process is currently running.",
			RecommendedFix:  "Remove the stale lock file (rm -f /var/run/zypp.pid).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	switch {
	case strings.Contains(lower, "signature verification failed") || strings.Contains(lower, "gpg check"):
		findings = append(findings, Finding{
			Code:            "ZYPPER_REPO_GPG_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "zypper reported a signature/GPG verification failure while refreshing a repository.",
			RecommendedFix:  "Import only the repository's vendor-published key (rpm --import <vendor-key-url>). Never accept an unverified key as a repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lower, "repository") && (strings.Contains(lower, "not found") || strings.Contains(lower, "forbidden")):
		findings = append(findings, Finding{
			Code:            "ZYPPER_REPO_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "zypper reported a repository that could not be reached or is no longer available.",
			RecommendedFix:  "Verify the repo URL with `zypper lr -u` and the vendor's current mirror before changing configuration.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lower, "could not resolve host") ||
		strings.Contains(lower, "failed to retrieve") ||
		strings.Contains(lower, "connection failed") ||
		(strings.Contains(lower, "repository") && strings.Contains(lower, "is invalid")):
		// Real zypper wording (verified against a live openSUSE container): "repository
		// '<name>' is invalid", "failed to retrieve new repository metadata", and a curl
		// error such as "could not resolve host: <host>" — none of which the original
		// "not found"/"forbidden" check above matches.
		findings = append(findings, Finding{
			Code:            "ZYPPER_REPO_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "zypper could not retrieve metadata from one or more configured repositories (DNS/connection failure).",
			RecommendedFix:  "Verify network connectivity and that the repo URL in `zypper lr -u` is still valid before changing configuration.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lower, "valid metadata not found") || strings.Contains(lower, "failed to download"):
		action := RepairAction{
			ID:              "zypper-clean-refresh",
			FindingCode:     "ZYPPER_METADATA_STALE",
			Risk:            RiskAutoSafe,
			Description:     "Clear and rebuild zypper's metadata cache.",
			Commands:        []string{"zypper clean --all", "zypper --non-interactive refresh"},
			Verification:    []string{"zypper lr -u"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityWarning,
			Risk:            RiskAutoSafe,
			Evidence:        "zypper metadata looks stale or incomplete.",
			RecommendedFix:  "Clear and rebuild the metadata cache (zypper clean --all && zypper refresh).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.TrimSpace(refresh) == "" {
		findings = append(findings, Finding{
			Code:            "ZYPPER_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "zypper returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
