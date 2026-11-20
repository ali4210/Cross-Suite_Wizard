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

	// Checked first, read-only: dnf5's own exclusive repository lock
	// (/var/lib/dnf/system-repo.lock, confirmed via /proc/<pid>/fd during a live
	// install in a Fedora container — NOT /var/lib/rpm/.rpm.lock, a different, RPM-
	// level lock) is only ever held during an active install/remove transaction, never
	// by repoinfo/makecache/history themselves (confirmed: running those concurrently
	// with a live install never blocks or errors) — so this tool's own read-only probe
	// commands below can never observe it by accident the way zypper's can via a
	// refresh failure. `flock -n` cannot detect it either: dnf5 locks via fcntl(2)
	// (confirmed: /proc/locks reports "POSIX ADVISORY", a different kernel lock
	// namespace from flock(2)), so this walks /proc/*/fd directly instead, exactly
	// mirroring the real, independently-captured dnf5 error ("Waiting for a lock on
	// the system repository. The following processes are currently accessing it:
	// <pid> <command>") without ever running a write operation to provoke it.
	lockCheck := runSudo(`
set +e
LOCKFILE=/var/lib/dnf/system-repo.lock
if [ ! -e "$LOCKFILE" ]; then
  echo 'DNF_LOCK_ABSENT'
else
  for pid_fd in /proc/[0-9]*/fd/*; do
    target=$(readlink "$pid_fd" 2>/dev/null)
    if [ "$target" = "$LOCKFILE" ]; then
      pid=$(echo "$pid_fd" | cut -d/ -f3)
      if [ -r "/proc/$pid/cmdline" ]; then
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        echo "DNF_LOCK_ACTIVE|pid=$pid|cmd=$cmd"
      fi
    fi
  done
fi
`)

	if strings.Contains(lockCheck, "DNF_LOCK_ACTIVE|") {
		findings = append(findings, Finding{
			Code:            "DNF_LOCK_ACTIVE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        pm + "'s repository lock is currently held by another process: " + strings.TrimSpace(lockCheck),
			RecommendedFix:  "Wait for the owning " + pm + " transaction to finish, then retry. Never remove this lock while its owning process is still running.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	inventory := runSudo(fmt.Sprintf(`
set +e
echo '=== REPOLIST ==='
%[1]s repoinfo 2>&1
echo '=== HISTORY ==='
%[1]s history list 2>&1 | head -20
echo '=== RPMDB ==='
rpm --quiet -Va --nofiles --nodeps 2>&1 | head -10
`, pm))

	cacheCheck := runSudo(fmt.Sprintf(`set +e
%[1]s makecache 2>&1
`, pm))

	repoFiles := runSudo(`set +e
cat /etc/yum.repos.d/*.repo 2>/dev/null
`)

	lowerCache := strings.ToLower(cacheCheck)
	lowerInventory := strings.ToLower(inventory)

	// Checked first and independently of makecache's own output: a repo whose
	// gpgkey= was swapped for a wrong-but-reachable key produces NO error at all from
	// `dnf makecache` whenever that repo doesn't sign its own metadata (repo_gpgcheck) —
	// confirmed live in a Fedora container for 16 of this catalog's 17 RPM vendors,
	// where the failure only ever surfaced during `dnf install` itself ("Transaction
	// failed: Signature verification failed... wrong key?"), which diagnose must never
	// run. This re-checks the repo's own configured key, read-only, against the known
	// vendor's pinned fingerprint instead.
	knownVendorKeyFindingAdded := false
	if profile, keyURL, ok := discoverKnownRPMVendorConfiguredKeyURL(a.Manager(), repoFiles); ok &&
		strings.HasPrefix(keyURL, "http") {
		keyCheck := runSudo(rpmConfiguredKeyScript(keyURL))
		if strings.TrimSpace(keyCheck) == "" || !hasAnyFingerprint(keyCheck, profile.ExpectedFingerprints) {
			findings = append(findings, Finding{
				Code:            "DNF_REPO_GPG_FAILURE",
				Severity:        SeverityError,
				Risk:            RiskKnownVendor,
				Evidence:        profile.DisplayName + "'s repository is configured with a signing key (" + keyURL + ") that does not match its pinned fingerprint.",
				RecommendedFix:  "Re-verify and re-import " + profile.DisplayName + "'s pinned signing key via the known-vendor RPM repair flow.",
				AutoRepairable:  true,
				RequiresConsent: true,
				RepositoryURL:   profile.AllowedURLPrefixes[0],
				SourceFile:      profile.RPMRepoFile,
			})
			knownVendorKeyFindingAdded = true
		}
	}

	switch {
	case !knownVendorKeyFindingAdded &&
		(strings.Contains(lowerCache, "gpg check failed") ||
			strings.Contains(lowerCache, "nokey") ||
			strings.Contains(lowerCache, "public key")):
		finding := Finding{
			Code:            "DNF_REPO_GPG_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        pm + " reported a GPG key verification failure while refreshing metadata.",
			RecommendedFix:  "Identify the repository's vendor-published key and import only that pinned key (rpm --import <vendor-key-url>). Never disable gpgcheck as a repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		}
		// If the broken repo's baseurl matches a known, pinned-fingerprint vendor
		// profile, attribute the finding to it so the known-vendor RPM repair pipeline
		// (rpm_repair.go) can offer a gated, verified re-trust instead of leaving this
		// permanently manual-only — mirroring how apt.go's diagnose resolves a
		// RepositoryURL per finding by parsing the actual configured source.
		if profile, repoFile, ok := discoverKnownRPMVendorRepo(a.Manager(), inventory); ok {
			finding.RepositoryURL = profile.AllowedURLPrefixes[0]
			finding.SourceFile = repoFile
			finding.Risk = RiskKnownVendor
			finding.AutoRepairable = true
			finding.RecommendedFix = "Re-verify and re-import " + profile.DisplayName + "'s pinned signing key via the known-vendor RPM repair flow."
		}
		findings = append(findings, finding)

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
		strings.Contains(lowerCache, "failed to download metadata") ||
		strings.Contains(lowerCache, "checksum error") ||
		strings.Contains(lowerCache, "unable to validate"):
		// The bare substring "cache" was removed from this check: confirmed live in a
		// Fedora 45 (dnf5) container that it produced a false positive on every single
		// HEALTHY run, since dnf5 itself always prints "Metadata cache created." on
		// success — that success banner contains the word "cache" too. The real dnf5
		// error wording for genuinely corrupted/stale metadata, captured by corrupting
		// a cached repodata file's checksum, is "Failed to download metadata... Error
		// loading local metadata for repository... Librepo error: Checksum error ...:
		// Unable to validate zchunk checksums" — none of which the original pattern
		// checked for at all.
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

	if strings.Contains(lowerInventory, "rpmdb: ") ||
		strings.Contains(lowerInventory, "error: rpmdb") ||
		strings.Contains(lowerInventory, "cannot open packages database") ||
		strings.Contains(lowerInventory, "cannot open packages index") ||
		strings.Contains(lowerInventory, "sqlite failure") ||
		strings.Contains(lowerInventory, "rpmtsopendb failed") {
		// Modern Fedora/RHEL 9+ (and dnf5) use a SQLite-backed rpmdb, not the classic BDB
		// "rpmdb:" wording. Verified against a live Fedora container: a corrupted
		// rpmdb.sqlite produces "error: cannot open Packages database in
		// /usr/lib/sysimage/rpm" / "error: sqlite failure: ... file is not a database" /
		// "rpmtsOpenDB failed". Both wordings are checked so either backend is caught.
		action := RepairAction{
			ID:          "dnf-rpmdb-rebuild",
			FindingCode: "DNF_RPMDB_CORRUPT",
			Risk:        RiskAutoSafe,
			Description: "Rebuild the local RPM database.",
			Commands:    []string{"rpm --rebuilddb"},
			// Not piped through `head`: a pipeline's exit status reflects the last
			// command, so `rpm -qa | head -1` would report success even when rpm itself
			// fails (verified live — this was a real bug, not just untested).
			Verification:    []string{"rpm -qa --qf '%{NAME}\\n' >/dev/null"},
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

	// D1(c) could not be reproduced live on dnf5: a Fedora 45 container, killed (-9) both
	// before and during "Running transaction" on several differently-sized installs, left
	// no partial package state (rpm correctly reports the target package "not installed"),
	// no stray transaction file, and — critically — no new `dnf history list`/`history
	// info` entry at all. dnf5's transaction/history commit appears to be atomic: either it
	// never reaches a kill-able window where a partial record would be written, or RPM's
	// own per-transaction atomicity already cleans up before history is touched. The
	// "aborted" substring below is kept as a safe, inert check (it matches nothing dnf5 is
	// known to ever print) in case it still applies to classic dnf4/yum on an older target,
	// which was not independently re-verified in this pass.
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
