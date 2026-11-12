package repohealer

import (
	"strings"
	"time"
)

// XBPSAdapter gives practical (not exhaustive) coverage of Void Linux xbps: it diagnoses
// unreachable repositories and signature problems as manual findings, and offers one safe
// auto-repair for a corrupted local repository index cache.
type XBPSAdapter struct{}

func (XBPSAdapter) Manager() PackageManager { return ManagerXBPS }

func (XBPSAdapter) Diagnose(
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

	sync := runSudo(`set +e
xbps-install -S 2>&1
`)
	lower := strings.ToLower(sync)

	switch {
	case strings.Contains(lower, "signature") || strings.Contains(lower, "pubkey") || strings.Contains(lower, "untrusted"):
		findings = append(findings, Finding{
			Code:            "XBPS_REPO_SIGNATURE_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "xbps-install reported a signature/trust failure while syncing a repository.",
			RecommendedFix:  "Verify /var/db/xbps/keys contains the correct vendor key for the repository in question before retrying.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lower, "could not fetch") || strings.Contains(lower, "name resolution") || strings.Contains(lower, "404"):
		findings = append(findings, Finding{
			Code:            "XBPS_REPO_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "xbps-install could not fetch repository data (DNS/404/connection failure).",
			RecommendedFix:  "Verify network connectivity and that the configured mirror in /etc/xbps.d is still valid.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lower, "corrupt") || strings.Contains(lower, "invalid repodata") || strings.Contains(lower, "unexpected"):
		action := RepairAction{
			ID:              "xbps-clean-resync",
			FindingCode:     "XBPS_REPODATA_CORRUPT",
			Risk:            RiskAutoSafe,
			Description:     "Remove the cached repository index and re-sync.",
			Commands:        []string{"rm -f /var/db/xbps/https*.plist", "xbps-install -S"},
			Verification:    []string{"xbps-install -S"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "xbps-install reported corrupted or invalid local repository data.",
			RecommendedFix:  "Remove the cached repository index and re-sync (rm -f /var/db/xbps/https*.plist && xbps-install -S).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.TrimSpace(sync) == "" {
		findings = append(findings, Finding{
			Code:            "XBPS_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "xbps-install returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
