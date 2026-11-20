package repohealer

import "testing"

// Regression tests for D2 (real-container zypper verification pass, 2026-11-20): a real
// safety bug in the stale-lock check, and the new active-lock finding it enabled. See
// zypper.go's comments for the exact captured wording each is based on.

// TestZypperAdapterNeverMisclassifiesAnActiveLockAsStale is a regression test for a real
// safety bug confirmed live in an openSUSE Leap 16.0 container: a genuinely active
// zypper process's /proc/<pid>/comm is "Zypp-main", never "zypper" — so the original
// check's `pgrep -x zypper` could NEVER match it, meaning a lock file was ALWAYS classified
// as stale (and auto-removable) even while a real zypper transaction actively held it.
func TestZypperAdapterNeverMisclassifiesAnActiveLockAsStale(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_PRESENT|ACTIVE|pid=171\n",
			"System management is locked by the application with pid 171 (zypper).\nClose this application before trying again.\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if containsCode(findingCodes(findings), "ZYPPER_LOCK_STALE") {
		t.Fatalf("an active lock must never be classified as stale, got %v", findingCodes(findings))
	}
	if !containsCode(findingCodes(findings), "ZYPPER_LOCK_ACTIVE") {
		t.Fatalf("expected ZYPPER_LOCK_ACTIVE finding, got %v", findingCodes(findings))
	}
	for _, a := range actions {
		if a.FindingCode == "ZYPPER_LOCK_ACTIVE" {
			t.Fatalf("an active lock must never have an auto-repair action, got %+v", a)
		}
	}
}

func TestZypperAdapterStaleLockStillDetectedWhenProcessIsGone(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_PRESENT|STALE|pid=171\n",
			"ok\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "ZYPPER_LOCK_STALE") {
		t.Fatalf("expected ZYPPER_LOCK_STALE finding, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "zypper-remove-stale-lock" || actions[0].Risk != RiskAutoSafe {
		t.Fatalf("expected the auto-safe stale-lock removal action, got %+v", actions)
	}
}

func TestZypperAdapterNoLockFindingWhenAbsent(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_ABSENT\n",
			"ok\n",
		},
	}

	_, findings, _ := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	if containsCode(findingCodes(findings), "ZYPPER_LOCK_STALE") || containsCode(findingCodes(findings), "ZYPPER_LOCK_ACTIVE") {
		t.Fatalf("did not expect a lock finding when absent, got %v", findingCodes(findings))
	}
}

// TestZypperAdapterGPGFailureAlreadyCatchesConfiguredKeySwap documents a real finding from
// D2 verification: unlike dnf5 (see dnf_d1_test.go), zypper's `refresh` DOES report a real
// error for a repo whose gpgkey= was swapped for a wrong-but-reachable key — confirmed live
// in an openSUSE Leap 16.0 container, even with repo_gpgcheck=0 explicitly set:
// "File 'repomd.xml' from repository '<name>' is signed with an unknown key '<id>'... repository
// '<name>' is invalid... Signature verification failed for repomd.xml". The existing
// ZYPPER_REPO_GPG_FAILURE check already matches this ("signature verification failed"), so
// no separate configured-key-freshness check (unlike dnf.go's) is needed for zypper.
func TestZypperAdapterGPGFailureAlreadyCatchesConfiguredKeySwap(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"LOCK_ABSENT\n",
			"File 'repomd.xml' from repository 'GitHub CLI' is signed with an unknown key '5612B36462313325'.\n" +
				"Repository 'GitHub CLI' is invalid.\n" +
				"[gh-cli|https://cli.github.com/packages/rpm] Failed to retrieve new repository metadata.\n" +
				"History:\n" +
				" - Signature verification failed for repomd.xml\n",
			"2 | gh-cli | GitHub CLI | Yes | ----      | Yes     | https://cli.github.com/packages/rpm\n",
		},
	}

	_, findings, actions := ZypperAdapter{}.Diagnose(exec, TargetFacts{}, Policy{})

	found := false
	for _, f := range findings {
		if f.Code == "ZYPPER_REPO_GPG_FAILURE" {
			found = true
			if f.Risk != RiskKnownVendor || !f.AutoRepairable {
				t.Fatalf("expected a known-vendor, auto-repairable finding, got: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("expected ZYPPER_REPO_GPG_FAILURE, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("GPG failures must never produce a direct repair action themselves, got %+v", actions)
	}
}
