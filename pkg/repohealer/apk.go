package repohealer

import (
	"strings"
	"time"
)

// APKAdapter diagnoses and repairs the most common Alpine apk failures: untrusted/bad
// signatures, unreachable mirrors, and a corrupted local index cache.
type APKAdapter struct{}

func (APKAdapter) Manager() PackageManager { return ManagerAPK }

func (APKAdapter) Diagnose(
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

	update := runSudo(`set +e
apk update 2>&1
`)
	lower := strings.ToLower(update)

	switch {
	case strings.Contains(lower, "untrusted signature") || strings.Contains(lower, "bad signature"):
		findings = append(findings, Finding{
			Code:            "APK_REPO_SIGNATURE_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "apk reported an untrusted or bad package-index signature.",
			RecommendedFix:  "Verify /etc/apk/keys contains the correct vendor public key for this Alpine release; restore it from a trusted Alpine ISO/image rather than fetching it ad hoc.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lower, "could not resolve") ||
		strings.Contains(lower, "network error") ||
		strings.Contains(lower, "temporary error") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "dns:") ||
		strings.Contains(lower, "name does not exist") ||
		strings.Contains(lower, "unable to connect"):
		findings = append(findings, Finding{
			Code:            "APK_REPO_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "apk could not reach one or more configured mirrors in /etc/apk/repositories.",
			RecommendedFix:  "Verify network/DNS connectivity and that the mirrors listed in /etc/apk/repositories are still valid for this Alpine release.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lower, "bad index") || strings.Contains(lower, "unexpected end of file") || strings.Contains(lower, "checksum"):
		action := RepairAction{
			ID:              "apk-clean-update",
			FindingCode:     "APK_INDEX_CORRUPT",
			Risk:            RiskAutoSafe,
			Description:     "Clear apk's cached index and re-fetch it.",
			Commands:        []string{"rm -rf /var/cache/apk/*", "apk update"},
			Verification:    []string{"apk update"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "apk reported a corrupted or truncated package index.",
			RecommendedFix:  "Clear the cached index and re-fetch it (rm -rf /var/cache/apk/* && apk update).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.TrimSpace(update) == "" {
		findings = append(findings, Finding{
			Code:            "APK_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "apk returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
