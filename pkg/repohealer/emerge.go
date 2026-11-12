package repohealer

import (
	"strings"
	"time"
)

// EmergeAdapter gives practical, diagnose-only coverage of Gentoo emerge/Portage. Portage
// tree sync failures are highly environment-specific (rsync mirrors, webrsync, delta sync,
// custom SYNC settings) and a bad automatic fix can leave the tree in a worse state than a
// stale one, so this adapter classifies the failure and recommends the standard manual
// remedy instead of proposing an auto-repairable action.
type EmergeAdapter struct{}

func (EmergeAdapter) Manager() PackageManager { return ManagerEmerge }

func (EmergeAdapter) Diagnose(
	exec Executor,
	facts TargetFacts,
	policy Policy,
) ([]CommandEvidence, []Finding, []RepairAction) {
	var evidence []CommandEvidence
	var findings []Finding

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

	syncOut := runSudo(`set +e
emerge --sync 2>&1 | tail -60
`)
	lower := strings.ToLower(syncOut)

	switch {
	case strings.Contains(lower, "could not resolve") ||
		strings.Contains(lower, "connection") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "getaddrinfo failed") ||
		strings.Contains(lower, "name or service not known") ||
		strings.Contains(lower, "exhausted addresses"):
		// Real wording (verified against a live Gentoo stage3 container with an
		// unreachable rsync mirror): "getaddrinfo failed for '<host>': name or service not
		// known" and "exhausted addresses for <host>". Checked before the generic rsync
		// case below so a DNS failure gets DNS-specific guidance, not just "rsync failed".
		findings = append(findings, Finding{
			Code:            "EMERGE_SYNC_NETWORK_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "emerge --sync could not reach its configured mirror (DNS/connection/timeout).",
			RecommendedFix:  "Verify network connectivity and the SYNC setting in /etc/portage/repos.conf before retrying.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lower, "signature") || strings.Contains(lower, "verification failed"):
		findings = append(findings, Finding{
			Code:            "EMERGE_SYNC_SIGNATURE_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "emerge --sync (webrsync-gpg) reported a signature verification failure on the Portage tree snapshot.",
			RecommendedFix:  "Do not disable signature verification. Re-fetch the snapshot and verify the Gentoo release key is current in your keyring.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lower, "rsync") && (strings.Contains(lower, "failed") || strings.Contains(lower, "error")):
		findings = append(findings, Finding{
			Code:            "EMERGE_RSYNC_FAILURE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "emerge --sync's rsync transport failed.",
			RecommendedFix:  "Consider switching to `emerge-webrsync` as a one-time fallback to fetch a fresh tree snapshot; review it manually before running, since it replaces the local Portage tree.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.TrimSpace(syncOut) == "" {
		findings = append(findings, Finding{
			Code:            "EMERGE_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "emerge returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, nil
}
