package repohealer

import (
	"os/exec"
	"strings"
	"testing"
)

// TestZypperAdapterDetectsAndRepairsRealStaleLockInAnOpenSUSEContainer reproduces, for
// real, the stale-lock scenario: start a real zypper transaction, kill it (leaving
// /var/run/zypp.pid behind with the now-dead PID), confirm the diagnose probe correctly
// classifies it as STALE (not active), applies the auto-safe removal, and confirms the
// target refreshes cleanly afterward.
func TestZypperAdapterDetectsAndRepairsRealStaleLockInAnOpenSUSEContainer(t *testing.T) {
	requireRPMContainerTestHost(t)

	ex := startRPMTestContainer(t, "opensuse/leap:latest", "cross-repohealer-zypper-d2-stale-test")

	cmd := exec.Command("docker", "exec", "-d", "cross-repohealer-zypper-d2-stale-test",
		"bash", "-c", "zypper install -y vim > /tmp/install.log 2>&1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to start the background install: %v\n%s", err, out)
	}

	var lockPID string
	for i := 0; i < 30; i++ {
		out, _ := ex.run("cat /var/run/zypp.pid 2>/dev/null")
		if strings.TrimSpace(out) != "" {
			lockPID = strings.TrimSpace(out)
			break
		}
		ex.run("sleep 0.5") //nolint:errcheck
	}
	if lockPID == "" {
		t.Skip("the background install never visibly wrote the lock file within the poll window on this runner")
	}

	killByCmdlinePrefix(ex, "zypper install")
	if out, err := ex.run("sleep 1; true"); err != nil {
		t.Fatalf("failed to wait after stopping the background install: %v\n%s", err, out)
	}

	adapter := ZypperAdapter{}
	_, findings, actions := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})
	if !containsCode(findingCodes(findings), "ZYPPER_LOCK_STALE") {
		t.Fatalf("expected ZYPPER_LOCK_STALE for a lock file whose owning process is dead, got: %v", findingCodes(findings))
	}
	if containsCode(findingCodes(findings), "ZYPPER_LOCK_ACTIVE") {
		t.Fatalf("a dead process's lock must never be classified as active, got: %v", findingCodes(findings))
	}

	var staleAction *RepairAction
	for i := range actions {
		if actions[i].FindingCode == "ZYPPER_LOCK_STALE" {
			staleAction = &actions[i]
		}
	}
	if staleAction == nil {
		t.Fatalf("expected a stale-lock repair action, got: %+v", actions)
	}

	execution := ApproveAndApplyGenericRepair(ex, actions, staleAction.ID, "yes")
	if execution.Decision != ApprovalExecutionExecuted || !execution.RepairResult.Applied {
		t.Fatalf("expected the stale-lock repair to apply, got decision=%v applied=%v error=%v",
			execution.Decision, execution.RepairResult.Applied, execution.Error)
	}

	// Not asserted here: that /var/run/zypp.pid is gone afterward. The repair's own
	// verification step runs a real `zypper refresh`, which recreates this exact file
	// for the duration of ITS OWN run (confirmed live) — a side effect of zypper
	// itself, unrelated to whether the repair worked. What actually matters is that
	// the ORIGINAL stale lock is no longer reported.
	_, findingsAfter, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})
	if containsCode(findingCodes(findingsAfter), "ZYPPER_LOCK_STALE") {
		t.Fatalf("expected the stale-lock finding to clear after the repair, got: %v", findingCodes(findingsAfter))
	}
}

// TestZypperAdapterDetectsRealActiveLockInAnOpenSUSEContainer reproduces, for real, a
// genuinely active zypper transaction holding the lock, confirming the diagnose probe
// correctly reports ZYPPER_LOCK_ACTIVE (never STALE) while it is alive, and that the
// finding clears once the owning process is gone — closing the real pgrep-based bug this
// pass found (a live zypper process's own /proc/<pid>/comm is "Zypp-main", which the
// original `pgrep -x zypper` check could never match).
func TestZypperAdapterDetectsRealActiveLockInAnOpenSUSEContainer(t *testing.T) {
	requireRPMContainerTestHost(t)

	ex := startRPMTestContainer(t, "opensuse/leap:latest", "cross-repohealer-zypper-d2-active-test")

	cmd := exec.Command("docker", "exec", "-d", "cross-repohealer-zypper-d2-active-test",
		"bash", "-c", "zypper install -y firefox > /tmp/install.log 2>&1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to start the background install: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		killByCmdlinePrefix(ex, "zypper install")
	})

	var lockSeen bool
	for i := 0; i < 30; i++ {
		out, _ := ex.run(`
LOCK_PID=$(cat /var/run/zypp.pid 2>/dev/null)
[ -n "$LOCK_PID" ] && [ -d "/proc/$LOCK_PID" ] && echo HELD
`)
		if strings.Contains(out, "HELD") {
			lockSeen = true
			break
		}
		ex.run("sleep 0.5") //nolint:errcheck
	}
	if !lockSeen {
		t.Skip("the background install never visibly held the lock within the poll window on this runner")
	}

	adapter := ZypperAdapter{}
	_, findingsWhileActive, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})
	if !containsCode(findingCodes(findingsWhileActive), "ZYPPER_LOCK_ACTIVE") {
		t.Fatalf("expected ZYPPER_LOCK_ACTIVE while the lock is genuinely held, got: %v", findingCodes(findingsWhileActive))
	}
	if containsCode(findingCodes(findingsWhileActive), "ZYPPER_LOCK_STALE") {
		t.Fatalf("a genuinely active lock must never be classified as stale (the real bug this pass fixed), got: %v", findingCodes(findingsWhileActive))
	}

	killByCmdlinePrefix(ex, "zypper install")
	if out, err := ex.run("sleep 1; true"); err != nil {
		t.Fatalf("failed to wait after stopping the background install: %v\n%s", err, out)
	}

	_, findingsAfter, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})
	if containsCode(findingCodes(findingsAfter), "ZYPPER_LOCK_ACTIVE") {
		t.Fatalf("expected the active-lock finding to clear once the owning process is gone, got: %v", findingCodes(findingsAfter))
	}
}

// TestZypperAdapterDetectsRealConfiguredKeySwapInAnOpenSUSEContainer reproduces, for real,
// a repo whose gpgkey= has been swapped for a different, reachable vendor's real key
// (GitHub CLI's repo configured with HashiCorp's real key), confirming the existing
// ZYPPER_REPO_GPG_FAILURE check already catches it via `zypper refresh` alone — unlike
// dnf5, which needed a dedicated new check for the equivalent scenario (see
// dnf_d1_container_test.go) — and that the known-vendor repair pipeline fixes it.
func TestZypperAdapterDetectsRealConfiguredKeySwapInAnOpenSUSEContainer(t *testing.T) {
	requireRPMContainerTestHost(t)
	t.Setenv(RPMRepairExecutionEnabledEnv, "true")

	ex := startRPMTestContainer(t, "opensuse/leap:latest", "cross-repohealer-zypper-d2-keyswap-test")

	setupScript := `
cat > /etc/zypp/repos.d/gh-cli.repo <<'EOF'
[gh-cli]
name=GitHub CLI
baseurl=https://cli.github.com/packages/rpm
enabled=1
autorefresh=1
type=rpm-md
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://rpm.releases.hashicorp.com/gpg
EOF
`
	if out, err := ex.run(setupScript); err != nil {
		t.Fatalf("failed to configure the test repo: %v\n%s", err, out)
	}

	refreshOut, _ := ex.run("zypper --non-interactive refresh gh-cli 2>&1")
	if !strings.Contains(strings.ToLower(refreshOut), "signature verification failed") {
		t.Fatalf("expected zypper to report a real signature failure for the swapped key, got:\n%s", refreshOut)
	}

	adapter := ZypperAdapter{}
	_, findings, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})

	var gpgFinding *Finding
	for i := range findings {
		if findings[i].Code == "ZYPPER_REPO_GPG_FAILURE" {
			gpgFinding = &findings[i]
		}
	}
	if gpgFinding == nil {
		t.Fatalf("expected ZYPPER_REPO_GPG_FAILURE, got: %v", findingCodes(findings))
	}
	if gpgFinding.Risk != RiskKnownVendor || !gpgFinding.AutoRepairable {
		t.Fatalf("expected a known-vendor, auto-repairable finding, got: %+v", gpgFinding)
	}

	result := Result{Target: TargetFacts{PackageManager: ManagerZypper}, Findings: findings}
	actions := BuildRPMRepairPlan(result)
	if len(actions) != 1 {
		t.Fatalf("expected exactly one repair action, got %d: %+v", len(actions), actions)
	}

	execution := ApproveAndApplyRPMRepair(ex, result, actions[0].ID, "yes")
	if execution.Decision != ApprovalExecutionExecuted || !execution.RepairResult.Applied {
		t.Fatalf("expected the repair to apply, got decision=%v applied=%v error=%v",
			execution.Decision, execution.RepairResult.Applied, execution.Error)
	}

	_, findingsAfter, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerZypper}, Policy{})
	if containsCode(findingCodes(findingsAfter), "ZYPPER_REPO_GPG_FAILURE") {
		t.Fatalf("expected no GPG finding after the repair, got: %v", findingCodes(findingsAfter))
	}
}
