package repohealer

import (
	"strings"
	"time"
)

// PacmanAdapter diagnoses and repairs the most common Arch/Manjaro pacman failures: a stale
// database lock, an invalid/untrusted keyring, unreachable mirrors, and a corrupted sync
// database cache.
type PacmanAdapter struct{}

func (PacmanAdapter) Manager() PackageManager { return ManagerPacman }

func (PacmanAdapter) Diagnose(
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
[ -f /var/lib/pacman/db.lck ] && echo LOCK_PRESENT || echo LOCK_ABSENT
pgrep -x pacman >/dev/null 2>&1 && echo PACMAN_RUNNING || echo PACMAN_NOT_RUNNING
`)

	syncCheck := runSudo(`set +e
pacman -Sy 2>&1
`)
	lowerSync := strings.ToLower(syncCheck)

	switch {
	case strings.Contains(lockState, "LOCK_PRESENT") && strings.Contains(lockState, "PACMAN_NOT_RUNNING"):
		action := RepairAction{
			ID:              "pacman-remove-stale-lock",
			FindingCode:     "PACMAN_DB_LOCKED",
			Risk:            RiskAutoSafe,
			Description:     "Remove pacman's stale database lock file.",
			Commands:        []string{"rm -f /var/lib/pacman/db.lck"},
			Verification:    []string{"pacman -Sy"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "/var/lib/pacman/db.lck exists but no pacman process is currently running, so this is a stale lock left over from an interrupted run.",
			RecommendedFix:  "Remove the stale lock file (rm -f /var/lib/pacman/db.lck).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)

	case strings.Contains(lockState, "LOCK_PRESENT") && strings.Contains(lockState, "PACMAN_RUNNING"):
		findings = append(findings, Finding{
			Code:            "PACMAN_DB_LOCKED_ACTIVE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "/var/lib/pacman/db.lck exists AND a pacman process is currently running — this is a real, active lock.",
			RecommendedFix:  "Wait for the running pacman process to finish. Do not remove the lock file while pacman is active.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	switch {
	case strings.Contains(lowerSync, "signature") &&
		(strings.Contains(lowerSync, "invalid") || strings.Contains(lowerSync, "unknown trust") || strings.Contains(lowerSync, "unknown public key")):
		action := RepairAction{
			ID:              "pacman-keyring-refresh",
			FindingCode:     "PACMAN_KEYRING_INVALID",
			Risk:            RiskApprovalNeeded,
			Description:     "Reinitialize and refresh the pacman keyring from the distribution's trusted keyring package.",
			Commands:        []string{"pacman-key --init", "pacman-key --populate archlinux", "pacman-key --refresh-keys"},
			Verification:    []string{"pacman -Sy"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskApprovalNeeded,
			Evidence:        "pacman reported an invalid, untrusted, or unknown package signature during sync.",
			RecommendedFix:  "Reinitialize and refresh the pacman keyring (pacman-key --init, --populate archlinux, --refresh-keys).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)

	case strings.Contains(lowerSync, "failed to retrieve") ||
		strings.Contains(lowerSync, "could not resolve host") ||
		strings.Contains(lowerSync, "404"):
		findings = append(findings, Finding{
			Code:            "PACMAN_MIRROR_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "pacman could not retrieve package databases from one or more configured mirrors.",
			RecommendedFix:  "Review /etc/pacman.d/mirrorlist. If reflector is installed, regenerate it (e.g. reflector --latest 20 --sort rate --save /etc/pacman.d/mirrorlist) after reviewing the change — this is not run automatically.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lowerSync, "database file") &&
		(strings.Contains(lowerSync, "corrupted") || strings.Contains(lowerSync, "invalid or corrupted")):
		action := RepairAction{
			ID:              "pacman-rebuild-sync-db",
			FindingCode:     "PACMAN_SYNC_DB_CORRUPT",
			Risk:            RiskAutoSafe,
			Description:     "Remove the corrupted sync database cache and re-sync.",
			Commands:        []string{"rm -f /var/lib/pacman/sync/*.db*", "pacman -Sy"},
			Verification:    []string{"pacman -Sy"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "pacman reported a corrupted sync database.",
			RecommendedFix:  "Remove the corrupted sync database cache and re-sync (rm -f /var/lib/pacman/sync/*.db* && pacman -Sy) — this only rebuilds a local cache, it does not touch installed packages.",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.TrimSpace(syncCheck) == "" {
		findings = append(findings, Finding{
			Code:            "PACMAN_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "pacman returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
