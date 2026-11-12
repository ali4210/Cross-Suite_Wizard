package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func findingCodes(findings []Finding) []string {
	codes := make([]string, 0, len(findings))
	for _, f := range findings {
		codes = append(codes, f.Code)
	}
	return codes
}

func containsCode(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestDNFAdapterStaleCacheProposesCleanAction(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== REPOLIST ===\nok\n=== HISTORY ===\n=== RPMDB ===\n",
			"Failed to synchronize cache for repo 'fedora'\n",
		},
	}

	_, findings, actions := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_METADATA_STALE") {
		t.Fatalf("expected DNF_METADATA_STALE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "dnf-stale-cache-clean" {
		t.Fatalf("expected dnf-stale-cache-clean action, got %+v", actions)
	}
}

func TestDNFAdapterGPGFailureIsManualOnly(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"GPG check FAILED\n",
		},
	}

	_, findings, actions := DNFAdapter{BinaryName: "yum"}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_REPO_GPG_FAILURE") {
		t.Fatalf("expected DNF_REPO_GPG_FAILURE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("GPG failures must never produce an auto-repair action, got %+v", actions)
	}
}

func TestDNFAdapterRPMDBCorruptProposesRebuild(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\nerror: rpmdb: BDB0113 Thread/process failure\n",
			"ok\n",
		},
	}

	_, findings, actions := DNFAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_RPMDB_CORRUPT") {
		t.Fatalf("expected DNF_RPMDB_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "dnf-rpmdb-rebuild" {
		t.Fatalf("expected dnf-rpmdb-rebuild action, got %+v", actions)
	}
}

// Regression test for real rpmdb corruption wording confirmed against a live Fedora
// container: modern Fedora/RHEL 9+ uses a SQLite-backed rpmdb, not the classic BDB
// "rpmdb:" wording the original pattern only checked for. Also confirms the verification
// command no longer pipes through `head`, which silently discarded rpm's own exit code.
func TestDNFAdapterRPMDBCorruptMatchesModernSQLiteWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n" +
				"error: sqlite failure: CREATE TABLE IF NOT EXISTS 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL): file is not a database\n" +
				"error: cannot open Packages index using sqlite - No such file or directory (2)\n" +
				"error: cannot open Packages database in /usr/lib/sysimage/rpm\n",
			"ok\n",
		},
	}

	_, findings, actions := DNFAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_RPMDB_CORRUPT") {
		t.Fatalf("expected DNF_RPMDB_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 {
		t.Fatalf("expected exactly one repair action, got %+v", actions)
	}
	if strings.Contains(actions[0].Verification[0], "head") {
		t.Fatalf("verification command still pipes through head, which discards rpm's real exit code: %q", actions[0].Verification[0])
	}
}

// PacmanAdapter now issues 4 RunSudo calls in order: lock state, keyring check, local
// sync-db read, and `pacman -Sy`. pacmanBaselineOutputs returns the first three as
// "nothing wrong here" so each test only needs to override the specific one it's probing.
func pacmanBaselineOutputs(lockState string) []string {
	return []string{lockState, "KEYRING_OK\n", "core 1.0.0-1\n"}
}

func TestPacmanAdapterStaleLockProposesRemoval(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(pacmanBaselineOutputs("LOCK_PRESENT\nPACMAN_NOT_RUNNING\n"), "ok\n"),
	}

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_DB_LOCKED") {
		t.Fatalf("expected PACMAN_DB_LOCKED finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "pacman-remove-stale-lock" {
		t.Fatalf("expected pacman-remove-stale-lock action, got %+v", actions)
	}
}

func TestPacmanAdapterActiveLockIsNotTouched(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(pacmanBaselineOutputs("LOCK_PRESENT\nPACMAN_RUNNING\n"), "ok\n"),
	}

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_DB_LOCKED_ACTIVE") {
		t.Fatalf("expected PACMAN_DB_LOCKED_ACTIVE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("an active lock must never be auto-removed, got %+v", actions)
	}
}

func TestPacmanAdapterKeyringInvalidProposesRefresh(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(
			pacmanBaselineOutputs("LOCK_ABSENT\nPACMAN_NOT_RUNNING\n"),
			"error: core: signature from \"Foo\" is unknown trust\n",
		),
	}

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_KEYRING_INVALID") {
		t.Fatalf("expected PACMAN_KEYRING_INVALID finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "pacman-keyring-refresh" {
		t.Fatalf("expected pacman-keyring-refresh action, got %+v", actions)
	}
}

// Regression test for real pacman wording confirmed against a live Arch container with no
// keyring initialized at all: "warning: public keyring not found; have you run
// 'pacman-key --init'?" / "error: required key missing from keyring" — none of which
// contain "signature"/"invalid"/"unknown trust". This is also the far more common
// real-world keyring failure (a fresh/uninitialized keyring) vs. a genuinely invalid
// signature, and `pacman -Sy` alone never exercises signature checking at all.
func TestPacmanAdapterUninitializedKeyringMatchesRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(
			pacmanBaselineOutputs("LOCK_ABSENT\nPACMAN_NOT_RUNNING\n"),
			"ok\n",
		),
	}
	// Override the keyring-check output (index 1) to reflect an uninitialized keyring.
	exec.runSudoOutputs[1] = "KEYRING_UNINITIALIZED\n"

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_KEYRING_INVALID") {
		t.Fatalf("expected PACMAN_KEYRING_INVALID finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "pacman-keyring-refresh" {
		t.Fatalf("expected pacman-keyring-refresh action, got %+v", actions)
	}
}

// Regression test for real pacman wording confirmed against a live Arch container: a
// corrupted local sync db produces "error: could not read db 'core' (missing type keyword
// in mtree specification)" when read directly — but running `pacman -Sy` first silently
// re-downloads and overwrites the corruption with no error at all, so the adapter must
// read the local db BEFORE triggering a resync (which is why this patches the dbReadCheck
// output at index 2, not the syncCheck output at index 3).
func TestPacmanAdapterCorruptSyncDBMatchesRealWordingReadBeforeResync(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(
			pacmanBaselineOutputs("LOCK_ABSENT\nPACMAN_NOT_RUNNING\n"),
			"ok\n",
		),
	}
	exec.runSudoOutputs[2] = "error: could not read db 'core' (missing type keyword in mtree specification)\n"

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_SYNC_DB_CORRUPT") {
		t.Fatalf("expected PACMAN_SYNC_DB_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "pacman-rebuild-sync-db" {
		t.Fatalf("expected pacman-rebuild-sync-db action, got %+v", actions)
	}
}

// Regression test for real pacman wording confirmed against a live Arch container with an
// unreachable mirror: "error: failed retrieving file 'core.db' from <host> : could not
// resolve host: <host>" — the original pattern checked "failed to retrieve" (missing
// "to"), which doesn't match, though the separate "could not resolve host" check happened
// to save it; this locks in both phrasings.
func TestPacmanAdapterMirrorUnreachableMatchesRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: append(
			pacmanBaselineOutputs("LOCK_ABSENT\nPACMAN_NOT_RUNNING\n"),
			"error: failed retrieving file 'core.db' from totally-nonexistent-mirror.invalid : could not resolve host: totally-nonexistent-mirror.invalid\n"+
				"warning: fatal error from totally-nonexistent-mirror.invalid, skipping for the remainder of this transaction\n"+
				"error: failed to synchronize all databases (failed to retrieve some files)\n",
		),
	}

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_MIRROR_UNREACHABLE") {
		t.Fatalf("expected PACMAN_MIRROR_UNREACHABLE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("an unreachable mirror must never produce an auto-repair action, got %+v", actions)
	}
}

func TestZypperAdapterStaleLockProposesRemoval(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_PRESENT\nZYPPER_NOT_RUNNING\n",
			"ok\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "ZYPPER_LOCK_STALE") {
		t.Fatalf("expected ZYPPER_LOCK_STALE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "zypper-remove-stale-lock" {
		t.Fatalf("expected zypper-remove-stale-lock action, got %+v", actions)
	}
}

func TestZypperAdapterGPGFailureIsManualOnly(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_ABSENT\nZYPPER_NOT_RUNNING\n",
			"Signature verification failed for repository\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "ZYPPER_REPO_GPG_FAILURE") {
		t.Fatalf("expected ZYPPER_REPO_GPG_FAILURE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("GPG failures must never produce an auto-repair action, got %+v", actions)
	}
}

// Regression test for real zypper wording confirmed against a live openSUSE Leap
// container: zypper reports "repository '<name>' is invalid" / "failed to retrieve new
// repository metadata" / "could not resolve host: <host>" on an unreachable repo — none of
// which the original "not found"/"forbidden" check matched.
func TestZypperAdapterUnreachableRepoMatchesRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_ABSENT\nZYPPER_NOT_RUNNING\n",
			"retrieving repository 'broken repo' metadata [.error]\n" +
				"repository 'broken repo' is invalid.\n" +
				"[broken|http://totally-nonexistent-mirror.invalid/repo/] failed to retrieve new repository metadata.\n" +
				"history:\n" +
				" - download (curl) error for 'http://totally-nonexistent-mirror.invalid/repo/content':\n" +
				"   error message: Could not resolve host: totally-nonexistent-mirror.invalid\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "ZYPPER_REPO_UNREACHABLE") {
		t.Fatalf("expected ZYPPER_REPO_UNREACHABLE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("an unreachable repo must never produce an auto-repair action, got %+v", actions)
	}
}

func TestAPKAdapterCorruptIndexProposesCleanUpdate(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"ERROR: bad index checksum\n",
		},
	}

	_, findings, actions := APKAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "APK_INDEX_CORRUPT") {
		t.Fatalf("expected APK_INDEX_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "apk-clean-update" {
		t.Fatalf("expected apk-clean-update action, got %+v", actions)
	}
}

func TestAPKAdapterUntrustedSignatureIsManualOnly(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"ERROR: untrusted signature\n",
		},
	}

	_, findings, actions := APKAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "APK_REPO_SIGNATURE_FAILURE") {
		t.Fatalf("expected APK_REPO_SIGNATURE_FAILURE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("signature failures must never produce an auto-repair action, got %+v", actions)
	}
}

// Regression test for real apk wording confirmed against a live Alpine container: apk
// reports "connection refused" / "dns: name does not exist" on an unreachable mirror, not
// "could not resolve" or "network error" as originally assumed.
func TestAPKAdapterUnreachableMirrorMatchesRealWording(t *testing.T) {
	cases := []string{
		"warning: updating and opening http://127.0.0.1:9/alpine/v3.19/main/x86_64/apkindex.tar.gz: connection refused\n1 unavailable, 0 stale; 16 distinct packages available\n",
		"warning: updating and opening http://totally-nonexistent-mirror.invalid/alpine/v3.19/main/x86_64/apkindex.tar.gz: dns: name does not exist\n1 unavailable, 0 stale; 16 distinct packages available\n",
	}

	for _, out := range cases {
		exec := &fakeExecutor{runSudoOutputs: []string{out}}
		_, findings, actions := APKAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})
		if !containsCode(findingCodes(findings), "APK_REPO_UNREACHABLE") {
			t.Fatalf("output %q: expected APK_REPO_UNREACHABLE finding, got %v", out, findingCodes(findings))
		}
		if len(actions) != 0 {
			t.Fatalf("output %q: unreachable mirror must never produce an auto-repair action, got %+v", out, actions)
		}
	}
}

func TestXBPSAdapterCorruptRepodataProposesResync(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"xbps-install: corrupt repodata archive\n",
		},
	}

	_, findings, actions := XBPSAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "XBPS_REPODATA_CORRUPT") {
		t.Fatalf("expected XBPS_REPODATA_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "xbps-clean-resync" {
		t.Fatalf("expected xbps-clean-resync action, got %+v", actions)
	}
}

// Regression tests for real xbps-install wording confirmed against a live Void Linux
// container. Neither real message matched the original patterns, and the original repair
// command (rm -f /var/db/xbps/https*.plist) never matched anything real — the repodata
// cache actually lives in a per-mirror directory.
func TestXBPSAdapterUnreachableMirrorMatchesRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"error: [reposync] failed to fetch file `http://totally-nonexistent-mirror.invalid/current/x86_64-repodata': no address record\n" +
				"[*] updating repository `http://totally-nonexistent-mirror.invalid/current/x86_64-repodata' ...\n",
		},
	}

	_, findings, actions := XBPSAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "XBPS_REPO_UNREACHABLE") {
		t.Fatalf("expected XBPS_REPO_UNREACHABLE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("an unreachable mirror must never produce an auto-repair action, got %+v", actions)
	}
}

func TestXBPSAdapterCorruptRepodataMatchesRealWordingAndFixesRealPath(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"ERROR: failed to open repodata: /var/db/xbps/https___repo-default_voidlinux_org_current/x86_64-repodata: Invalid or incomplete multibyte or wide character\n" +
				"ERROR: Package 'bash' not found in repository pool.\n",
		},
	}

	_, findings, actions := XBPSAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "XBPS_REPODATA_CORRUPT") {
		t.Fatalf("expected XBPS_REPODATA_CORRUPT finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 {
		t.Fatalf("expected exactly one repair action, got %+v", actions)
	}
	if strings.Contains(actions[0].Commands[0], "*.plist") {
		t.Fatalf("repair command still targets the wrong (never-matching) path: %q", actions[0].Commands[0])
	}
	if !strings.Contains(actions[0].Commands[0], "https___") {
		t.Fatalf("repair command should target the real per-mirror repodata directory, got %q", actions[0].Commands[0])
	}
}

func TestEmergeAdapterNeverProposesAutoAction(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"rsync_fetch: failed to fetch files\n",
		},
	}

	_, findings, actions := EmergeAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "EMERGE_RSYNC_FAILURE") {
		t.Fatalf("expected EMERGE_RSYNC_FAILURE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("emerge adapter is diagnose-only and must never propose an action, got %+v", actions)
	}
}

// Regression test for real emerge wording confirmed against a live Gentoo stage3
// container with an unreachable rsync mirror configured.
func TestEmergeAdapterDNSFailureMatchesRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			">>> syncing repository 'gentoo' into '/var/db/repos/gentoo'...\n" +
				"!!! getaddrinfo failed for 'totally-nonexistent-mirror.invalid': [errno -2] name or service not known\n" +
				">>> starting rsync with rsync://totally-nonexistent-mirror.invalid/gentoo-portage...\n" +
				"rsync: getaddrinfo: totally-nonexistent-mirror.invalid 873: name or service not known\n" +
				"rsync error: error in socket io (code 10) at clientserver.c(165) [receiver=3.5.1]\n" +
				"!!! exhausted addresses for totally-nonexistent-mirror.invalid\n",
		},
	}

	_, findings, actions := EmergeAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "EMERGE_SYNC_NETWORK_FAILURE") {
		t.Fatalf("expected EMERGE_SYNC_NETWORK_FAILURE finding (DNS-specific), got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("emerge adapter is diagnose-only and must never propose an action, got %+v", actions)
	}
}

func TestHomebrewAdapterUsesNonSudoChannel(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"Warning: Some installed formulae are outdated\n",
			"Already up-to-date.\n",
		},
	}

	_, findings, actions := HomebrewAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if len(exec.commands) != 2 || !strings.HasPrefix(exec.commands[0], "RUN:") || !strings.HasPrefix(exec.commands[1], "RUN:") {
		t.Fatalf("Homebrew diagnostics must use the non-sudo Run channel, got %v", exec.commands)
	}
	if !containsCode(findingCodes(findings), "BREW_STALE_CACHE") {
		t.Fatalf("expected BREW_STALE_CACHE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || !actions[0].RunAsNonRoot {
		t.Fatalf("expected a RunAsNonRoot brew-cleanup-cache action, got %+v", actions)
	}
}

func TestApplyGenericRepairActionSucceeds(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{"removed\n", "ok\n"},
	}

	action := RepairAction{
		ID:              "pacman-remove-stale-lock",
		Eligible:        true,
		RequiresConsent: true,
		Commands:        []string{"rm -f /var/lib/pacman/db.lck"},
		Verification:    []string{"pacman -Sy"},
	}

	got := ApproveAndApplyGenericRepair(exec, []RepairAction{action}, action.ID, "yes")

	if got.Decision != ApprovalExecutionExecuted {
		t.Fatalf("decision = %q, want executed; error = %v", got.Decision, got.Error)
	}
	if !got.RepairResult.Applied {
		t.Fatalf("expected repair to be applied: %v", got.Error)
	}
	if got.RepairResult.RolledBack {
		t.Fatal("successful repair must not roll back")
	}
}

func TestApplyGenericRepairActionRollsBackOnVerificationFailure(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{"removed\n"},
		runSudoErrors:  []error{nil, errors.New("verification failed")},
	}

	action := RepairAction{
		ID:              "pacman-remove-stale-lock",
		Eligible:        true,
		RequiresConsent: true,
		Commands:        []string{"rm -f /var/lib/pacman/db.lck"},
		Verification:    []string{"pacman -Sy"},
		Rollback:        []string{"touch /var/lib/pacman/db.lck"},
	}

	got := ApproveAndApplyGenericRepair(exec, []RepairAction{action}, action.ID, "yes")

	if got.RepairResult.Applied {
		t.Fatal("repair must not be marked applied when verification fails")
	}
	if !got.RepairResult.RolledBack {
		t.Fatal("expected rollback commands to run when verification fails and there is no snapshot")
	}
}

func TestApplyGenericRepairActionUsesNonSudoChannelWhenFlagged(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{"cleaned\n", "ok\n"},
	}

	action := RepairAction{
		ID:              "brew-cleanup-cache",
		Eligible:        true,
		RequiresConsent: true,
		Commands:        []string{"brew cleanup -s"},
		Verification:    []string{"brew doctor"},
		RunAsNonRoot:    true,
	}

	got := ApproveAndApplyGenericRepair(exec, []RepairAction{action}, action.ID, "yes")

	if !got.RepairResult.Applied {
		t.Fatalf("expected brew action to apply: %v", got.Error)
	}
	for _, cmd := range exec.commands {
		if strings.HasPrefix(cmd, "SUDO") {
			t.Fatalf("RunAsNonRoot action must never go through the sudo channel, got %v", exec.commands)
		}
	}
}

func TestApproveAndApplyGenericRepairDeclinesWithoutYes(t *testing.T) {
	exec := &fakeExecutor{}
	action := RepairAction{
		ID:              "pacman-remove-stale-lock",
		Eligible:        true,
		RequiresConsent: true,
		Commands:        []string{"rm -f /var/lib/pacman/db.lck"},
	}

	got := ApproveAndApplyGenericRepair(exec, []RepairAction{action}, action.ID, "no")

	if got.Decision != ApprovalExecutionDeclined {
		t.Fatalf("decision = %q, want declined", got.Decision)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a declined repair must never run any command, got %v", exec.commands)
	}
}

func TestCollectNetworkFactsDetectsDiskFull(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"=== DNS ===\ngithub.com has address 140.82.112.3\n" +
				"=== PROXY ===\n" +
				"=== CLOCK ===\n0\n" +
				"=== DISK ===\n/dev/sda1 1000000 990000 10000 99% /\n",
		},
	}

	_, findings := CollectNetworkFacts(exec)

	if !containsCode(findingCodes(findings), "NETWORK_DISK_SPACE_LOW") {
		t.Fatalf("expected NETWORK_DISK_SPACE_LOW finding, got %v", findingCodes(findings))
	}
}

func TestCollectNetworkFactsDiskFullEvidenceShowsRealDfAndCleanupCandidatesButNeverDeletes(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"=== DNS ===\ngithub.com has address 140.82.112.3\n" +
				"=== PROXY ===\n" +
				"=== CLOCK ===\n0\n" +
				"=== DISK ===\n/dev/sda1 1000000 990000 10000 99% /\n" +
				"=== CLEANUP ===\n512M\t/var/cache/apt/archives\n" +
				"120.3M\t/var/log/syslog\n",
		},
	}

	_, findings := CollectNetworkFacts(exec)

	var disk Finding
	for _, finding := range findings {
		if finding.Code == "NETWORK_DISK_SPACE_LOW" {
			disk = finding
		}
	}

	if !containsCode(findingCodes(findings), "NETWORK_DISK_SPACE_LOW") {
		t.Fatalf("expected NETWORK_DISK_SPACE_LOW finding, got %v", findingCodes(findings))
	}
	if !strings.Contains(disk.Evidence, "/dev/sda1 1000000 990000 10000 99% /") {
		t.Fatalf("evidence must include the real df -Pk output, got: %s", disk.Evidence)
	}
	if !strings.Contains(disk.Evidence, "/var/cache/apt/archives") || !strings.Contains(disk.Evidence, "/var/log/syslog") {
		t.Fatalf("evidence must list real cleanup candidates, got: %s", disk.Evidence)
	}
	if strings.Contains(disk.Evidence, "rm ") || strings.Contains(disk.RecommendedFix, "rm ") {
		t.Fatalf("disk-full finding must never recommend or perform a deletion, got evidence=%q fix=%q", disk.Evidence, disk.RecommendedFix)
	}
	if !strings.Contains(disk.RecommendedFix, "never deletes anything automatically") {
		t.Fatalf("fix text must state nothing is deleted automatically, got: %s", disk.RecommendedFix)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("disk/cleanup probing must be a single read-only command, got %d: %v", len(exec.commands), exec.commands)
	}
	if strings.Contains(exec.commands[0], "RUN:") == false {
		t.Fatalf("expected the probe to run via the non-sudo Run path, got: %s", exec.commands[0])
	}
}

func TestCollectNetworkFactsDetectsDNSFailure(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{
			"=== DNS ===\n" +
				"=== PROXY ===\n" +
				"=== CLOCK ===\n0\n" +
				"=== DISK ===\n/dev/sda1 1000000 100000 900000 10% /\n",
		},
	}

	_, findings := CollectNetworkFacts(exec)

	if !containsCode(findingCodes(findings), "NETWORK_DNS_RESOLUTION_FAILED") {
		t.Fatalf("expected NETWORK_DNS_RESOLUTION_FAILED finding, got %v", findingCodes(findings))
	}
}
