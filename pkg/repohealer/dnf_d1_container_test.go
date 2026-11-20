package repohealer

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDNFAdapterDetectsAndRepairsRealKeySwapInAFedoraContainer reproduces, for real, the
// D1(a) gap found while verifying this pass: configure Docker CE's real repo with
// HashiCorp's real (wrong-for-this-repo, but reachable) key, confirm `dnf makecache` alone
// shows no error at all (the common case: this repo doesn't sign its own metadata), confirm
// the new configured-key check still catches it, then confirm the existing known-vendor
// repair pipeline actually fixes it end-to-end.
func TestDNFAdapterDetectsAndRepairsRealKeySwapInAFedoraContainer(t *testing.T) {
	requireRPMContainerTestHost(t)
	t.Setenv(RPMRepairExecutionEnabledEnv, "true")

	ex := startRPMTestContainer(t, "fedora:latest", "cross-repohealer-dnf-d1-keyswap-test")

	if out, err := ex.run("dnf install -y gnupg2 curl >/dev/null 2>&1 && echo OK"); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("container setup failed: %v\n%s", err, out)
	}

	setupScript := `
cat > /etc/yum.repos.d/docker-ce.repo <<'EOF'
[docker-ce-stable]
name=Docker CE Stable
baseurl=https://download.docker.com/linux/fedora/$releasever/$basearch/stable
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://rpm.releases.hashicorp.com/gpg
EOF
`
	if out, err := ex.run(setupScript); err != nil {
		t.Fatalf("failed to configure the test repo: %v\n%s", err, out)
	}

	makecacheOut, err := ex.run("dnf makecache --repo=docker-ce-stable 2>&1")
	if err != nil {
		t.Fatalf("makecache unexpectedly failed: %v\n%s", err, makecacheOut)
	}
	if strings.Contains(strings.ToLower(makecacheOut), "gpg") || strings.Contains(strings.ToLower(makecacheOut), "nokey") {
		t.Fatalf("expected makecache to show NO gpg-related error for this swapped key (the real gap this closes), got:\n%s", makecacheOut)
	}

	adapter := DNFAdapter{BinaryName: "dnf"}
	_, findings, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerDNF}, Policy{})

	var gpgFinding *Finding
	for i := range findings {
		if findings[i].Code == "DNF_REPO_GPG_FAILURE" {
			gpgFinding = &findings[i]
		}
	}
	if gpgFinding == nil {
		t.Fatalf("expected the configured-key check to catch the swapped key despite a clean makecache, got findings: %v", findingCodes(findings))
	}
	if gpgFinding.Risk != RiskKnownVendor || !gpgFinding.AutoRepairable {
		t.Fatalf("expected a known-vendor, auto-repairable finding, got: %+v", gpgFinding)
	}

	result := Result{
		Target:   TargetFacts{PackageManager: ManagerDNF},
		Findings: findings,
	}
	actions := BuildRPMRepairPlan(result)
	if len(actions) != 1 {
		t.Fatalf("expected exactly one repair action, got %d: %+v", len(actions), actions)
	}

	execution := ApproveAndApplyRPMRepair(ex, result, actions[0].ID, "yes")
	if execution.Decision != ApprovalExecutionExecuted || !execution.RepairResult.Applied {
		t.Fatalf("expected the repair to apply, got decision=%v applied=%v error=%v",
			execution.Decision, execution.RepairResult.Applied, execution.Error)
	}

	_, findingsAfter, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerDNF}, Policy{})
	if containsCode(findingCodes(findingsAfter), "DNF_REPO_GPG_FAILURE") {
		t.Fatalf("expected no GPG finding after the repair, got: %v", findingCodes(findingsAfter))
	}
}

// killByCmdlinePrefix kills every process whose /proc/<pid>/cmdline starts with prefix,
// without depending on `pkill` — confirmed NOT installed in the plain fedora:latest image
// (silently "succeeding" with exit 127 under this file's earlier `pkill ... 2>/dev/null`,
// which never actually killed anything and caused a real test flake, not a product bug).
func killByCmdlinePrefix(ex dockerExecExecutor, prefix string) {
	ex.run(`
set +e
for pid in /proc/[0-9]*; do
  cmdline="$pid/cmdline"
  [ -r "$cmdline" ] || continue
  cmd=$(tr '\0' ' ' < "$cmdline" 2>/dev/null)
  case "$cmd" in
    "` + prefix + `"*) kill -9 "$(basename "$pid")" 2>/dev/null ;;
  esac
done
`) //nolint:errcheck
}

// TestDNFAdapterDetectsActiveLockInARealFedoraContainer reproduces D1(d) for real: starts a
// genuine `dnf install` in the background so it actively holds dnf5's own repository lock
// (/var/lib/dnf/system-repo.lock, confirmed via /proc/<pid>/fd — not /var/lib/rpm/.rpm.lock),
// confirms the diagnose probe reports it (naming the real owning process), then confirms the
// finding clears once that process is gone.
func TestDNFAdapterDetectsActiveLockInARealFedoraContainer(t *testing.T) {
	requireRPMContainerTestHost(t)

	ex := startRPMTestContainer(t, "fedora:latest", "cross-repohealer-dnf-d1-lock-test")

	cmd := exec.Command("docker", "exec", "-d", "cross-repohealer-dnf-d1-lock-test",
		"bash", "-c", "dnf install -y firefox > /tmp/install.log 2>&1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to start the background install: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		killByCmdlinePrefix(ex, "dnf install")
	})

	// Poll cheaply (just the lock file's holder, not a full Diagnose) for the lock to
	// actually be held — the install needs a moment to resolve dependencies first. A
	// full Diagnose call is expensive (inventory + makecache + repo-file read), so it is
	// only run once, after this confirms the lock is actually held.
	var lockSeen bool
	for i := 0; i < 30; i++ {
		out, _ := ex.run(`
LOCKFILE=/var/lib/dnf/system-repo.lock
[ -e "$LOCKFILE" ] || exit 0
for pid_fd in /proc/[0-9]*/fd/*; do
  [ "$(readlink "$pid_fd" 2>/dev/null)" = "$LOCKFILE" ] && echo HELD && exit 0
done
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

	adapter := DNFAdapter{BinaryName: "dnf"}
	_, findingsWhileLocked, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerDNF}, Policy{})
	if !containsCode(findingCodes(findingsWhileLocked), "DNF_LOCK_ACTIVE") {
		t.Fatalf("expected DNF_LOCK_ACTIVE while the lock is held, got: %v", findingCodes(findingsWhileLocked))
	}
	for _, f := range findingsWhileLocked {
		if f.Code == "DNF_LOCK_ACTIVE" && !strings.Contains(f.Evidence, "dnf install") {
			t.Fatalf("expected the lock finding to name the real owning command, got: %s", f.Evidence)
		}
	}

	killByCmdlinePrefix(ex, "dnf install")
	if out, err := ex.run("sleep 1; true"); err != nil {
		t.Fatalf("failed to wait after stopping the background install: %v\n%s", err, out)
	}

	_, findingsAfter, _ := adapter.Diagnose(ex, TargetFacts{PackageManager: ManagerDNF}, Policy{})
	if containsCode(findingCodes(findingsAfter), "DNF_LOCK_ACTIVE") {
		t.Fatalf("expected the lock finding to clear once the owning process is gone, got: %v", findingCodes(findingsAfter))
	}
}
