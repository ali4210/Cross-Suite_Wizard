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

func TestPacmanAdapterStaleLockProposesRemoval(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_PRESENT\nPACMAN_NOT_RUNNING\n",
			"ok\n",
		},
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
		runSudoOutputs: []string{
			"LOCK_PRESENT\nPACMAN_RUNNING\n",
			"ok\n",
		},
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
		runSudoOutputs: []string{
			"LOCK_ABSENT\nPACMAN_NOT_RUNNING\n",
			"error: core: signature from \"Foo\" is unknown trust\n",
		},
	}

	_, findings, actions := PacmanAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "PACMAN_KEYRING_INVALID") {
		t.Fatalf("expected PACMAN_KEYRING_INVALID finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "pacman-keyring-refresh" {
		t.Fatalf("expected pacman-keyring-refresh action, got %+v", actions)
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
