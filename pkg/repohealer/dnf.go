package repohealer

import (
	"fmt"
	"strings"
	"time"
)

// DNFAdapter diagnoses and repairs the most common dnf/yum repository and package-database
// failures: broken/unreachable repo definitions, GPG key problems, stale metadata cache,
// a corrupted local RPM database, and interrupted transactions. BinaryName selects which of
// the two (functionally compatible) CLIs to invoke on the target.
type DNFAdapter struct {
	BinaryName string
}

func (a DNFAdapter) Manager() PackageManager {
	if a.BinaryName == "yum" {
		return ManagerYUM
	}
	return ManagerDNF
}

func (a DNFAdapter) Diagnose(
	exec Executor,
	facts TargetFacts,
	policy Policy,
) ([]CommandEvidence, []Finding, []RepairAction) {
	pm := a.BinaryName
	if pm == "" {
		pm = "dnf"
	}

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

	inventory := runSudo(fmt.Sprintf(`
set +e
echo '=== REPOLIST ==='
%[1]s repolist -v 2>&1
echo '=== HISTORY ==='
%[1]s history list 2>&1 | head -20
echo '=== RPMDB ==='
rpm --quiet -Va --nofiles --nodeps 2>&1 | head -10
`, pm))

	cacheCheck := runSudo(fmt.Sprintf(`set +e
%[1]s makecache 2>&1
`, pm))

	lowerCache := strings.ToLower(cacheCheck)
	lowerInventory := strings.ToLower(inventory)

	switch {
	case strings.Contains(lowerCache, "gpg check failed") ||
		strings.Contains(lowerCache, "nokey") ||
		strings.Contains(lowerCache, "public key"):
		findings = append(findings, Finding{
			Code:            "DNF_REPO_GPG_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        pm + " reported a GPG key verification failure while refreshing metadata.",
			RecommendedFix:  "Identify the repository's vendor-published key and import only that pinned key (rpm --import <vendor-key-url>). Never disable gpgcheck as a repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})

	case strings.Contains(lowerCache, "cannot find a valid baseurl") ||
		strings.Contains(lowerCache, "could not resolve") ||
		strings.Contains(lowerCache, "errno 14") ||
		strings.Contains(lowerCache, "status code: 404"):
		findings = append(findings, Finding{
			Code:            "DNF_REPO_UNREACHABLE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        pm + " could not reach one or more configured repositories (DNS/404/connection failure).",
			RecommendedFix:  "Verify the repo's baseurl/mirrorlist is still valid and that the host can reach it before changing any configuration.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})

	case strings.Contains(lowerCache, "failed to synchronize cache") ||
		strings.Contains(lowerCache, "repomd.xml") ||
		strings.Contains(lowerCache, "cache"):
		action := RepairAction{
			ID:              "dnf-stale-cache-clean",
			FindingCode:     "DNF_METADATA_STALE",
			Risk:            RiskAutoSafe,
			Description:     "Clear and rebuild " + pm + "'s metadata cache.",
			Commands:        []string{pm + " clean all", pm + " makecache"},
			Verification:    []string{pm + " repolist"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityWarning,
			Risk:            RiskAutoSafe,
			Evidence:        pm + " metadata cache looks stale or corrupted.",
			RecommendedFix:  "Clear and rebuild the metadata cache (" + pm + " clean all && " + pm + " makecache).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.Contains(lowerInventory, "rpmdb: ") || strings.Contains(lowerInventory, "error: rpmdb") {
		action := RepairAction{
			ID:              "dnf-rpmdb-rebuild",
			FindingCode:     "DNF_RPMDB_CORRUPT",
			Risk:            RiskAutoSafe,
			Description:     "Rebuild the local RPM database.",
			Commands:        []string{"rpm --rebuilddb"},
			Verification:    []string{"rpm -qa --qf '%{NAME}\\n' | head -1 >/dev/null"},
			RequiresConsent: true,
			Eligible:        true,
			Target:          facts,
		}
		findings = append(findings, Finding{
			Code:            action.FindingCode,
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "The local RPM database appears corrupted.",
			RecommendedFix:  "Rebuild the RPM database (rpm --rebuilddb) before retrying any install/update.",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, action)
	}

	if strings.Contains(lowerInventory, "aborted") {
		findings = append(findings, Finding{
			Code:            "DNF_TRANSACTION_INTERRUPTED",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        pm + " history shows an aborted/interrupted transaction.",
			RecommendedFix:  "Review '" + pm + " history list' and consider '" + pm + " history undo last' only after confirming it is safe for this host.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.TrimSpace(cacheCheck) == "" {
		findings = append(findings, Finding{
			Code:            "DNF_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        pm + " returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings, actions
}
