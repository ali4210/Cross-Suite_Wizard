package repohealer

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// dockerExecExecutor implements Executor by shelling into a running Docker container as
// root — the container runs as root by default, so RunSudo/RunSudoWithLabel need no actual
// privilege escalation inside it, unlike a real SSH session to a non-root user.
type dockerExecExecutor struct {
	container string
}

func (d dockerExecExecutor) run(script string) (string, error) {
	cmd := exec.Command("docker", "exec", d.container, "bash", "-c", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (d dockerExecExecutor) Run(command string) (string, error)    { return d.run(command) }
func (d dockerExecExecutor) RunSudo(script string) (string, error) { return d.run(script) }
func (d dockerExecExecutor) RunSudoWithLabel(script, _ string) (string, error) {
	return d.run(script)
}

func requireRPMContainerTestHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("skipping: real-container RPM repair verification needs a Linux Docker host")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: docker not found on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("skipping: docker daemon not reachable on this runner")
	}
}

func startRPMTestContainer(t *testing.T, image, name string) dockerExecExecutor {
	t.Helper()

	exec.Command("docker", "rm", "-f", name).Run() //nolint:errcheck

	runCmd := exec.Command("docker", "run", "-d", "--rm", "--name", name, image, "sleep", "600")
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run failed: %v\noutput:\n%s", err, out)
	}

	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", name).Run() //nolint:errcheck
	})

	return dockerExecExecutor{container: name}
}

// TestDNFRepairAppliesAndVerifiesForRealInAFedoraContainer runs the full RPM repair
// pipeline (preview -> typed approval -> operator-policy gate -> snapshot -> fingerprint
// verification -> rpm --import -> write .repo file -> post-repair dnf makecache) against a
// real, live HashiCorp repository in a real Fedora container, then confirms the repo file
// and imported GPG key genuinely exist on disk/in the RPM database afterward.
func TestDNFRepairAppliesAndVerifiesForRealInAFedoraContainer(t *testing.T) {
	requireRPMContainerTestHost(t)
	withRPMRepairEnabled(t)

	ex := startRPMTestContainer(t, "fedora:latest", "cross-repohealer-dnf-apply-test")

	if out, err := ex.run("dnf install -y gnupg2 curl >/dev/null 2>&1 && echo OK"); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("container setup failed: %v\n%s", err, out)
	}

	profile, ok := FindVendorProfileByID(ManagerDNF, "hashicorp")
	if !ok {
		t.Fatal("expected hashicorp DNF profile to be registered")
	}

	result := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "fedora",
			PackageManager: ManagerDNF,
		},
		Findings: []Finding{
			{
				Code:          "DNF_REPO_GPG_FAILURE",
				RepositoryURL: profile.AllowedURLPrefixes[0],
				SourceFile:    profile.RPMRepoFile,
			},
		},
	}

	actions := BuildRPMRepairPlan(result)
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(actions), actions)
	}
	if !actions[0].Eligible {
		t.Fatalf("expected action to be eligible, blocked reason: %s", actions[0].BlockReason)
	}

	execution := ApproveAndApplyRPMRepair(ex, result, actions[0].ID, "yes")

	if execution.Decision != ApprovalExecutionExecuted {
		t.Fatalf("expected ApprovalExecutionExecuted, got %v (error: %v)", execution.Decision, execution.Error)
	}
	if !execution.RepairResult.Applied {
		t.Fatalf("expected the repair to apply successfully: %+v", execution.RepairResult)
	}

	repoFileOut, err := ex.run(fmt.Sprintf("cat %s", profile.RPMRepoFile))
	if err != nil || !strings.Contains(repoFileOut, profile.RPMBaseURL) {
		t.Fatalf("expected %s to contain the rendered baseurl; got (err=%v):\n%s", profile.RPMRepoFile, err, repoFileOut)
	}

	keyListOut, err := ex.run("rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n'")
	if err != nil {
		t.Fatalf("failed to list imported gpg-pubkey entries: %v\n%s", err, keyListOut)
	}
	if !strings.Contains(keyListOut, "d55c0d1ac78a8d8126cb631cfc9ca96aca026560") {
		t.Fatalf("expected the HashiCorp key fingerprint to be imported into the RPM database, got:\n%s", keyListOut)
	}

	verifyOut, err := ex.run("dnf makecache --repo=hashicorp 2>&1")
	if err != nil {
		t.Fatalf("expected the newly repaired repo to refresh cleanly: %v\n%s", err, verifyOut)
	}
}

// TestDNFRepairRollsBackForRealOnFingerprintMismatch deliberately points a repair at a
// real, live, but WRONG key (HashiCorp's actual key fingerprint does not match a
// deliberately-fabricated expected fingerprint) inside a real Fedora container, and
// confirms the pipeline refuses to import the key, makes no lasting change, and the
// rollback leaves no new .repo file or GPG key behind.
func TestDNFRepairRollsBackForRealOnFingerprintMismatch(t *testing.T) {
	requireRPMContainerTestHost(t)
	withRPMRepairEnabled(t)

	ex := startRPMTestContainer(t, "fedora:latest", "cross-repohealer-dnf-rollback-test")

	if out, err := ex.run("dnf install -y gnupg2 curl >/dev/null 2>&1 && echo OK"); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("container setup failed: %v\n%s", err, out)
	}

	preExistingKeysBefore, err := ex.run("rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' 2>/dev/null || true")
	if err != nil {
		t.Fatalf("failed to snapshot pre-existing keys: %v", err)
	}

	badProfile := VendorProfile{
		ID:             "rollback-test-vendor",
		DisplayName:    "Rollback Test Vendor",
		PackageManager: ManagerDNF,
		AllowedURLPrefixes: []string{
			"https://rpm.releases.hashicorp.com/RHEL/9/x86_64/stable-rollback-test",
		},
		KeyURL:      "https://rpm.releases.hashicorp.com/gpg", // real, reachable key...
		KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-rollback-test",
		ExpectedFingerprints: []string{
			// ...but this fabricated fingerprint can never match it, forcing a real
			// fingerprint-mismatch rollback against a live key download.
			"0000000000000000000000000000000000000000",
		},
		RPMRepoID:   "rollback-test-vendor",
		RPMBaseURL:  "https://rpm.releases.hashicorp.com/RHEL/9/x86_64/stable",
		RPMRepoFile: "/etc/yum.repos.d/rollback-test-vendor.repo",
	}

	result := Result{
		Target: TargetFacts{Platform: PlatformLinux, Distribution: "fedora", PackageManager: ManagerDNF},
	}

	action := RepairAction{
		ID:                   RPMRepairActionID(badProfile.ID, "DNF_REPO_GPG_FAILURE"),
		FindingCode:          "DNF_REPO_GPG_FAILURE",
		Eligible:             true,
		ProfileID:            badProfile.ID,
		ProfileDisplayName:   badProfile.DisplayName,
		RepositoryURL:        badProfile.AllowedURLPrefixes[0],
		Target:               result.Target,
		KeyURL:               badProfile.KeyURL,
		ExpectedFingerprints: badProfile.ExpectedFingerprints,
		KeyringPath:          badProfile.KeyringPath,
		SourceFile:           badProfile.RPMRepoFile,
	}

	repairResult := applyKnownRPMRepairActionWithVerification(ex, result.Target, badProfile, action)

	if repairResult.Applied {
		t.Fatal("a fingerprint mismatch must never be applied")
	}
	if !repairResult.RolledBack {
		t.Fatalf("expected a rollback to have run, got: %+v", repairResult)
	}
	if repairResult.Error == nil {
		t.Fatal("expected an error describing the fingerprint mismatch")
	}

	repoFileCheck, _ := ex.run(fmt.Sprintf("test -f %s && echo PRESENT || echo ABSENT", badProfile.RPMRepoFile))
	if !strings.Contains(repoFileCheck, "ABSENT") {
		t.Fatalf("expected no .repo file to be left behind after rollback, got: %s", repoFileCheck)
	}

	keyListAfter, err := ex.run("rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' 2>/dev/null || true")
	if err != nil {
		t.Fatalf("failed to list keys after rollback: %v", err)
	}
	if strings.TrimSpace(keyListAfter) != strings.TrimSpace(preExistingKeysBefore) {
		t.Fatalf(
			"expected the set of imported GPG keys to be unchanged after rollback.\nbefore:\n%s\nafter:\n%s",
			preExistingKeysBefore,
			keyListAfter,
		)
	}
}

// TestZypperRepairAppliesAndVerifiesForRealInAnOpenSUSEContainer runs the full RPM repair
// pipeline against a real, live GitHub CLI repository in a real openSUSE Leap container,
// confirming the zypper-specific verification path (`zypper --non-interactive refresh`)
// and repo file location (/etc/zypp/repos.d) both work for real, not just dnf's.
func TestZypperRepairAppliesAndVerifiesForRealInAnOpenSUSEContainer(t *testing.T) {
	requireRPMContainerTestHost(t)
	withRPMRepairEnabled(t)

	ex := startRPMTestContainer(t, "opensuse/leap:latest", "cross-repohealer-zypper-apply-test")

	profile, ok := FindVendorProfileByID(ManagerZypper, "github-cli-rpm")
	if !ok {
		t.Fatal("expected github-cli-rpm Zypper profile to be registered")
	}

	result := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "opensuse-leap",
			PackageManager: ManagerZypper,
		},
		Findings: []Finding{
			{
				Code:          "ZYPPER_REPO_GPG_FAILURE",
				RepositoryURL: profile.AllowedURLPrefixes[0],
				SourceFile:    profile.RPMRepoFile,
			},
		},
	}

	actions := BuildRPMRepairPlan(result)
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(actions), actions)
	}

	start := time.Now()
	execution := ApproveAndApplyRPMRepair(ex, result, actions[0].ID, "yes")
	t.Logf("zypper repair took %s", time.Since(start))

	if execution.Decision != ApprovalExecutionExecuted {
		t.Fatalf("expected ApprovalExecutionExecuted, got %v (error: %v)", execution.Decision, execution.Error)
	}
	if !execution.RepairResult.Applied {
		t.Fatalf("expected the repair to apply successfully: %+v", execution.RepairResult)
	}

	repoFileOut, err := ex.run(fmt.Sprintf("cat %s", profile.RPMRepoFile))
	if err != nil || !strings.Contains(repoFileOut, profile.RPMBaseURL) {
		t.Fatalf("expected %s to contain the rendered baseurl; got (err=%v):\n%s", profile.RPMRepoFile, err, repoFileOut)
	}
}
