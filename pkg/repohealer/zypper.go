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

	// Real bug found and fixed here (confirmed live in an openSUSE Leap 16.0 container):
	// the original check used `pgrep -x zypper`, but a real, actively-running zypper
	// process's /proc/<pid>/comm is "Zypp-main", never "zypper" — so `pgrep -x zypper`
	// can NEVER match it, meaning ZYPPER_NOT_RUNNING was always reported even while a
	// genuine, live zypper transaction held the lock. That made this tool's own
	// "stale, safe to auto-remove" classification always true whenever the lock file
	// existed at all — a real safety bug: it could offer to delete an ACTIVE process's
	// lock file during a live transaction. Fixed by reading the PID the lock file
	// itself records (confirmed real: `cat /var/run/zypp.pid` prints the holder's PID)
	// and checking whether that exact PID is still alive via /proc, which needs no
	// process-name matching at all.
	lockState := runSudo(`
set +e
LOCK_PID=$(cat /var/run/zypp.pid 2>/dev/null)
if [ -z "$LOCK_PID" ]; then
  echo LOCK_ABSENT
elif [ -d "/proc/$LOCK_PID" ]; then
  echo "LOCK_PRESENT|ACTIVE|pid=$LOCK_PID"
else
  echo "LOCK_PRESENT|STALE|pid=$LOCK_PID"
fi
`)

	refresh := runSudo(`set +e
zypper --non-interactive refresh 2>&1
`)
	lower := strings.ToLower(refresh)

	repoList := runSudo(`set +e
zypper --non-interactive lr -u 2>&1
`)

	if strings.Contains(lockState, "LOCK_PRESENT|STALE") {
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
			Evidence:        "/var/run/zypp.pid exists but its recorded process (" + strings.TrimSpace(lockState) + ") is no longer running.",
			RecommendedFix:  "Remove the stale lock file (rm -f /var/run/zypp.pid).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	} else if strings.Contains(lockState, "LOCK_PRESENT|ACTIVE") {
		// Real wording captured live from a genuine concurrent zypper collision in an
		// openSUSE Leap 16.0 container: "System management is locked by the
		// application with pid <pid> (zypper). Close this application before trying
		// again." Manual-only, by design: this must never be auto-repaired — the lock
		// is legitimately held by a live transaction.
		findings = append(findings, Finding{
			Code:            "ZYPPER_LOCK_ACTIVE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "zypper's repository lock is currently held by another active process: " + strings.TrimSpace(lockState),
			RecommendedFix:  "Wait for the owning zypper transaction to finish, then retry. Never remove this lock while its owning process is still running.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	switch {
	case strings.Contains(lower, "signature verification failed") || strings.Contains(lower, "gpg check"):
		finding := Finding{
			Code:            "ZYPPER_REPO_GPG_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "zypper reported a signature/GPG verification failure while refreshing a repository.",
			RecommendedFix:  "Import only the repository's vendor-published key (rpm --import <vendor-key-url>). Never accept an unverified key as a repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		}
		// See the matching comment in dnf.go: attribute to a known, pinned-fingerprint
		// vendor profile when the broken repo's URI matches one, so the known-vendor
		// RPM repair pipeline can offer a gated, verified re-trust.
		if profile, repoFile, ok := discoverKnownRPMVendorRepo(ManagerZypper, repoList); ok {
			finding.RepositoryURL = profile.AllowedURLPrefixes[0]
			finding.SourceFile = repoFile
			finding.Risk = RiskKnownVendor
			finding.AutoRepairable = true
			finding.RecommendedFix = "Re-verify and re-import " + profile.DisplayName + "'s pinned signing key via the known-vendor RPM repair flow."
		}
		findings = append(findings, finding)

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
