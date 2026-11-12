package repohealer

import (
	"strings"
	"time"
)

// HomebrewAdapter diagnoses common macOS Homebrew health problems via `brew doctor` and
// `brew update`. Homebrew refuses to run as root, so diagnostics and repairs use exec.Run
// (the plain, non-sudo channel) and the one offered repair action is marked RunAsNonRoot.
type HomebrewAdapter struct{}

func (HomebrewAdapter) Manager() PackageManager { return ManagerHomebrew }

func (HomebrewAdapter) Diagnose(
	exec Executor,
	facts TargetFacts,
	policy Policy,
) ([]CommandEvidence, []Finding, []RepairAction) {
	var evidence []CommandEvidence
	var findings []Finding
	var actions []RepairAction

	run := func(command string) string {
		started := time.Now()
		output, err := exec.Run(command)
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

	doctorOut := run(`brew doctor 2>&1`)
	updateOut := run(`brew update 2>&1`)
	combined := strings.ToLower(doctorOut + "\n" + updateOut)

	switch {
	case strings.Contains(combined, "permission") &&
		(strings.Contains(combined, "not writable") || strings.Contains(combined, "incorrect permission")):
		findings = append(findings, Finding{
			Code:            "BREW_PREFIX_PERMISSIONS",
			Severity:        SeverityError,
			Risk:            RiskApprovalNeeded,
			Evidence:        "brew doctor reported that part of the Homebrew prefix is not writable by the current user.",
			RecommendedFix:  "Review brew doctor's exact suggested chown/chmod command for this host's prefix (/usr/local or /opt/homebrew) before running it manually — it is prefix- and account-specific, so it is not auto-applied here.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(combined, "is not a valid tap") || strings.Contains(combined, "invalid tap"):
		findings = append(findings, Finding{
			Code:            "BREW_BROKEN_TAP",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "brew update reported a broken or invalid tap.",
			RecommendedFix:  "Identify the broken tap from the output above, then `brew untap <tap>` and re-add it with `brew tap <tap>` if still needed.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.Contains(combined, "warning") || strings.Contains(combined, "outdated") {
		action := RepairAction{
			ID:                  "brew-cleanup-cache",
			FindingCode:         "BREW_STALE_CACHE",
			Risk:                RiskAutoSafe,
			Description:         "Prune old downloads and outdated cached versions.",
			Commands:            []string{"brew cleanup -s"},
			Verification:        []string{"brew doctor"},
			RequiresConsent:     true,
			Eligible:            true,
			Target:              facts,
			RunAsNonRoot:        true,
			UseHomebrewSnapshot: true,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityInfo,
			Risk:            RiskAutoSafe,
			Evidence:        "brew doctor/update reported warnings or an outdated state that stale cached downloads can contribute to.",
			RecommendedFix:  "Run `brew cleanup -s` to prune old downloads and cached versions.",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.TrimSpace(doctorOut) == "" && strings.TrimSpace(updateOut) == "" {
		findings = append(findings, Finding{
			Code:            "BREW_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "brew returned no diagnostic output; Homebrew may not be installed or not on PATH for this session.",
			RecommendedFix:  "Confirm Homebrew is installed and reachable on PATH for the connecting (non-root) user.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
