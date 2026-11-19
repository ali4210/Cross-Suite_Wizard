package repohealer

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func withRPMRepairEnabled(t *testing.T) {
	t.Helper()
	t.Setenv(RPMRepairExecutionEnabledEnv, "true")
}

func withRPMRepairDisabled(t *testing.T) {
	t.Helper()
	t.Setenv(RPMRepairExecutionEnabledEnv, "")
}

func hashicorpDNFResult() Result {
	return Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "fedora",
			Version:        "45",
			Architecture:   "x86_64",
			PackageManager: ManagerDNF,
		},
		Findings: []Finding{
			{
				Code:          "DNF_REPO_GPG_FAILURE",
				RepositoryURL: "https://rpm.releases.hashicorp.com/RHEL/9/x86_64/stable",
				SourceLine:    0,
			},
		},
	}
}

func TestRenderRPMRepoFileAlwaysUsesLocalKeyringPathAndGPGCheck1(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerDNF, "https://rpm.releases.hashicorp.com/RHEL/9/x86_64/stable")
	if !ok {
		t.Fatal("expected HashiCorp RPM profile to be registered")
	}

	rendered, err := RenderRPMRepoFile(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(rendered, "[hashicorp]") {
		t.Fatalf("expected rendered repo section [hashicorp], got: %s", rendered)
	}
	if !strings.Contains(rendered, "gpgcheck=1") {
		t.Fatalf("expected gpgcheck=1, got: %s", rendered)
	}
	if !strings.Contains(rendered, "gpgkey=file://"+profile.KeyringPath) {
		t.Fatalf("expected gpgkey to point at the local verified key copy %q, got: %s", profile.KeyringPath, rendered)
	}
	if strings.Contains(rendered, profile.KeyURL) {
		t.Fatalf("rendered repo file must never reference the bare vendor KeyURL directly: %s", rendered)
	}
}

func TestRenderRPMRepoFileRejectsNonRPMProfile(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://apt.releases.hashicorp.com")
	if !ok {
		t.Fatal("expected HashiCorp APT profile to be registered")
	}

	if _, err := RenderRPMRepoFile(profile); err == nil {
		t.Fatal("expected an error for a non-RPM profile")
	}
}

func TestIsKnownRPMRepairFindingOnlyMatchesDNFAndZypperGPGFailures(t *testing.T) {
	cases := map[string]bool{
		"DNF_REPO_GPG_FAILURE":     true,
		"ZYPPER_REPO_GPG_FAILURE":  true,
		"APT_KEYRING_PATH_MISSING": false,
		"DNF_RPMDB_CORRUPT":        false,
	}

	for code, want := range cases {
		if got := IsKnownRPMRepairFinding(code); got != want {
			t.Errorf("IsKnownRPMRepairFinding(%q) = %v, want %v", code, got, want)
		}
	}
}

func TestCanonicalRPMManagerMapsYUMToDNF(t *testing.T) {
	if got := canonicalRPMManager(ManagerYUM); got != ManagerDNF {
		t.Fatalf("expected YUM to canonicalize to DNF, got %v", got)
	}
	if got := canonicalRPMManager(ManagerZypper); got != ManagerZypper {
		t.Fatalf("expected Zypper to remain Zypper, got %v", got)
	}
}

func TestExtractRPMRepoBaseURLsParsesRealDNF5RepoinfoWording(t *testing.T) {
	// Captured verbatim from `dnf repoinfo hashicorp` against a live third-party repo in
	// a real Fedora 45 (dnf5) container, 2026-11-20.
	output := `Repo ID              : hashicorp
Name                 : Hashicorp Stable - x86_64
Status               : enabled
URLs                 :
  Base URL           : https://rpm.releases.hashicorp.com/fedora/45/x86_64/stable
OpenPGP              :
  Keys               : file:///etc/pki/rpm-gpg/RPM-GPG-KEY-hashicorp
`

	urls := extractRPMRepoBaseURLs(ManagerDNF, output)
	if len(urls) != 1 || urls[0] != "https://rpm.releases.hashicorp.com/fedora/45/x86_64/stable" {
		t.Fatalf("expected exactly one parsed baseurl, got %v", urls)
	}
}

func TestExtractRPMRepoBaseURLsHandlesMultiMirrorSuffix(t *testing.T) {
	// Captured verbatim from `dnf repoinfo fedora` (the distro's own multi-mirror repo)
	// against a live Fedora 45 container, 2026-11-20 — confirms the "(N more)" suffix a
	// repo with several mirrors prints is stripped and only the first URL is kept.
	output := `  Base URL           : rsync://mirror.example.invalid/fedora/linux/releases/45/Everything/x86_64/os/ (27 more)`

	urls := extractRPMRepoBaseURLs(ManagerDNF, output)
	if len(urls) != 1 || urls[0] != "rsync://mirror.example.invalid/fedora/linux/releases/45/Everything/x86_64/os/" {
		t.Fatalf("expected the multi-mirror suffix stripped, got %v", urls)
	}
}

func TestExtractRPMRepoBaseURLsParsesRealZypperLrUWording(t *testing.T) {
	// Captured verbatim from `zypper lr -u` against a live openSUSE Leap 16.0 container,
	// 2026-11-19.
	output := `# | Alias                       | Name                      | Enabled | GPG Check | Refresh | URI
--+-----------------------------+---------------------------+---------+-----------+---------+-------------------------------------------------------------------------
1 | openSUSE:repo-oss           | repo-oss (16.0)           | Yes     | ( p) Yes  | Yes     | http://cdn.opensuse.org/distribution/leap/16.0/repo/oss/x86_64
2 | gh-cli                      | GitHub CLI                | Yes     | ( p) Yes  | Yes     | https://cli.github.com/packages/rpm
`

	urls := extractRPMRepoBaseURLs(ManagerZypper, output)
	if len(urls) != 2 {
		t.Fatalf("expected 2 parsed URIs, got %v", urls)
	}
	if urls[1] != "https://cli.github.com/packages/rpm" {
		t.Fatalf("expected the second URI to be the gh-cli repo, got %q", urls[1])
	}
}

func TestDiscoverKnownRPMVendorRepoMatchesHashiCorp(t *testing.T) {
	output := `  Base URL           : https://rpm.releases.hashicorp.com/RHEL/9/x86_64/stable`

	profile, repoFile, ok := discoverKnownRPMVendorRepo(ManagerDNF, output)
	if !ok {
		t.Fatal("expected a known-vendor match for HashiCorp")
	}
	if profile.ID != "hashicorp" {
		t.Fatalf("expected hashicorp profile, got %q", profile.ID)
	}
	if repoFile != profile.RPMRepoFile {
		t.Fatalf("expected repo file %q, got %q", profile.RPMRepoFile, repoFile)
	}
}

func TestDiscoverKnownRPMVendorRepoNoMatchForUnknownRepo(t *testing.T) {
	output := `  Base URL           : https://totally-unknown.example.invalid/repo`

	_, _, ok := discoverKnownRPMVendorRepo(ManagerDNF, output)
	if ok {
		t.Fatal("expected no known-vendor match for an unrecognized repository")
	}
}

func TestRPMRepairExecutionEnabledRequiresExactlyTrue(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"True":  true,
		"TRUE":  true,
		"":      false,
		"1":     false,
		"yes":   false,
		"false": false,
	}

	for value, want := range cases {
		t.Setenv(RPMRepairExecutionEnabledEnv, value)
		if got := RPMRepairExecutionEnabled(); got != want {
			t.Errorf("RPMRepairExecutionEnabled() with env=%q = %v, want %v", value, got, want)
		}
	}
}

func TestBuildRPMRepairPlanBlocksWhenOperatorPolicyDisabled(t *testing.T) {
	withRPMRepairDisabled(t)

	actions := BuildRPMRepairPlan(hashicorpDNFResult())
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %d", len(actions))
	}

	action := actions[0]
	if action.Eligible {
		t.Fatal("expected action to be blocked when the operator policy is disabled")
	}
	if action.Risk != RiskBlocked {
		t.Fatalf("expected RiskBlocked, got %v", action.Risk)
	}
	if !strings.Contains(action.BlockReason, RPMRepairExecutionEnabledEnv) {
		t.Fatalf("expected block reason to name the policy env var, got: %s", action.BlockReason)
	}
}

func TestBuildRPMRepairPlanRendersSourceWhenOperatorPolicyEnabled(t *testing.T) {
	withRPMRepairEnabled(t)

	actions := BuildRPMRepairPlan(hashicorpDNFResult())
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %d", len(actions))
	}

	action := actions[0]
	if !action.Eligible {
		t.Fatalf("expected action to be eligible, blocked reason: %s", action.BlockReason)
	}
	if action.RenderedSource == "" {
		t.Fatal("expected a rendered .repo file preview")
	}
	if action.ProfileID != "hashicorp" {
		t.Fatalf("expected hashicorp profile, got %q", action.ProfileID)
	}
}

func TestApplyKnownRPMRepairsReturnsNoActionForUnknownFinding(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{}

	result := Result{
		Target: TargetFacts{PackageManager: ManagerDNF},
		Findings: []Finding{
			{Code: "DNF_REPO_GPG_FAILURE", RepositoryURL: "https://unknown.example.invalid/repo"},
		},
	}

	got := ApplyKnownRPMRepairs(exec, result)
	if got.Attempted {
		t.Fatal("unknown repository must not start a repair attempt")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unknown repository must not execute commands, got %d", len(exec.commands))
	}
}

func TestApplyKnownRPMRepairsBlocksBeforeSnapshotWhenPolicyDisabled(t *testing.T) {
	withRPMRepairDisabled(t)
	exec := &fakeExecutor{}

	got := ApplyKnownRPMRepairs(exec, hashicorpDNFResult())

	if got.Applied {
		t.Fatal("must not apply when operator policy is disabled")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("must not execute any command when blocked before snapshot, got %d", len(exec.commands))
	}
	if got.Error == nil {
		t.Fatal("expected an error when no eligible action exists")
	}
}

func TestApplyKnownRPMRepairsBlocksWhenRPMLockIsActive(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			"RPM_LOCK_ACTIVE|owners=1234",
		},
	}

	got := ApplyKnownRPMRepairs(exec, hashicorpDNFResult())

	if got.Applied {
		t.Fatal("must not apply while an RPM lock is active")
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected exactly the lock probe to run, got %d commands: %v", len(exec.commands), exec.commands)
	}
	if !strings.Contains(exec.commands[0], "Checking RPM Package-Manager Lock State") {
		t.Fatalf("expected a lock-state probe, got: %s", exec.commands[0])
	}
}

func TestApplyKnownRPMRepairsRollsBackOnFingerprintMismatch(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"", // pre-existing gpg-pubkey list
			"", // snapshot create
			"", // pruneImportedRPMGPGKeys: current gpg-pubkey list (unchanged)
			"", // snapshot restore
		},
		runSudoLabelOutputs: []string{
			"", // lock probe: unlocked
			"REPAIR_ERROR|fingerprint_mismatch|profile=hashicorp",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 22"),
		},
	}

	got := ApplyKnownRPMRepairs(exec, hashicorpDNFResult())

	if !got.Attempted {
		t.Fatal("expected a repair attempt")
	}
	if got.Applied {
		t.Fatal("fingerprint mismatch must not apply the repair")
	}
	if !got.RolledBack {
		t.Fatal("fingerprint mismatch must trigger a rollback")
	}
	if got.Error == nil {
		t.Fatal("expected an error")
	}
	if got.Snapshot.Path == "" {
		t.Fatal("expected snapshot metadata to have been recorded before the repair attempt")
	}

	foundRepairLabel := false
	for _, command := range exec.commands {
		if strings.Contains(command, "Restoring HashiCorp RPM Trust") {
			foundRepairLabel = true
		}
	}
	if !foundRepairLabel {
		t.Fatalf("expected the repair script to run under the profile's RPM trust label, got: %v", exec.commands)
	}
}

func TestApplyKnownRPMRepairsRollsBackOnVerificationFailure(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"", // pre-existing gpg-pubkey list
			"", // snapshot create
			"gpg-pubkey-d55c0d1ac78a8d8126cb631cfc9ca96aca026560-6aa195cc", // prune: current list now includes the newly-imported key
			"", // rpm -e of the newly-imported key
			"", // snapshot restore
		},
		runSudoLabelOutputs: []string{
			"", // lock probe: unlocked
			"REPAIR_APPLIED|hashicorp|fingerprint=D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
			"Fedora Repo gpgcheck: gpg check failed",
		},
		runSudoLabelErrors: []error{
			nil,
			nil,
			errors.New("exit status 1"),
		},
	}

	got := ApplyKnownRPMRepairs(exec, hashicorpDNFResult())

	if !got.Attempted {
		t.Fatal("expected a repair attempt")
	}
	if got.Applied {
		t.Fatal("a failed verification must not be marked applied")
	}
	if !got.RolledBack {
		t.Fatal("a failed verification must trigger a rollback")
	}
	if !strings.Contains(got.VerificationOut, "gpg check failed") {
		t.Fatalf("expected verification evidence, got: %s", got.VerificationOut)
	}

	foundKeyRemoval := false
	for _, command := range exec.commands {
		if strings.Contains(command, "rpm -e") && strings.Contains(command, "gpg-pubkey-d55c0d1ac78a8d8126cb631cfc9ca96aca026560-6aa195cc") {
			foundKeyRemoval = true
		}
	}
	if !foundKeyRemoval {
		t.Fatalf("expected rollback to remove only the newly-imported GPG key, got: %v", exec.commands)
	}
}

func TestPruneImportedRPMGPGKeysNeverRemovesAPreExistingKey(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"gpg-pubkey-aaaa-1\ngpg-pubkey-bbbb-2\n", // current: one pre-existing + one new
		},
	}

	preExisting := map[string]bool{"gpg-pubkey-aaaa-1": true}

	if err := pruneImportedRPMGPGKeys(exec, preExisting); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(exec.commands) != 2 {
		t.Fatalf("expected exactly 2 commands (list + one rpm -e), got %d: %v", len(exec.commands), exec.commands)
	}
	if strings.Contains(exec.commands[1], "gpg-pubkey-aaaa-1") {
		t.Fatalf("must never remove a pre-existing key, got: %s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[1], "gpg-pubkey-bbbb-2") {
		t.Fatalf("expected the newly-imported key to be removed, got: %s", exec.commands[1])
	}
}

func TestApproveAndApplyRPMRepairDeclinesWithoutExactConfirmation(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{}

	result := hashicorpDNFResult()
	actions := BuildRPMRepairPlan(result)
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %d", len(actions))
	}

	got := ApproveAndApplyRPMRepair(exec, result, actions[0].ID, "not yes")

	if got.Decision != ApprovalExecutionDeclined {
		t.Fatalf("expected ApprovalExecutionDeclined, got %v", got.Decision)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("declined approval must not execute any command, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyRPMRepairBlocksWhenOperatorPolicyDisabledEvenWithYes(t *testing.T) {
	withRPMRepairDisabled(t)
	exec := &fakeExecutor{}

	result := hashicorpDNFResult()
	// The action ID is still computable even though the plan itself reports no eligible
	// action when the policy is disabled.
	actionID := RPMRepairActionID("hashicorp", "DNF_REPO_GPG_FAILURE")

	got := ApproveAndApplyRPMRepair(exec, result, actionID, "yes")

	if got.Decision != ApprovalExecutionBlocked {
		t.Fatalf("expected ApprovalExecutionBlocked, got %v", got.Decision)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("must not execute any command when blocked by operator policy, got %d", len(exec.commands))
	}
}

func TestApproveAndApplyRPMRepairActionNotFoundForUnknownID(t *testing.T) {
	withRPMRepairEnabled(t)
	exec := &fakeExecutor{}

	got := ApproveAndApplyRPMRepair(exec, hashicorpDNFResult(), "does-not-exist", "yes")

	if got.Decision != ApprovalExecutionActionNotFound {
		t.Fatalf("expected ApprovalExecutionActionNotFound, got %v", got.Decision)
	}
}

func TestBuildRPMRepairAuditEventClassifiesFingerprintMismatch(t *testing.T) {
	execution := ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action:   RepairAction{ID: "rpm-hashicorp-dnf_repo_gpg_failure", ProfileID: "hashicorp"},
		RepairResult: RepairResult{
			Attempted: true,
			Error:     errors.New("key import/repo repair failed: exit status 22"),
		},
		Error: errors.New("key import/repo repair failed: exit status 22"),
	}

	audit := BuildRPMRepairAuditEvent(execution, execution.RepairResult.Snapshot.CreatedAt)

	if audit.Event != "rpm_repository_repair" {
		t.Fatalf("expected event name rpm_repository_repair, got %q", audit.Event)
	}
	if audit.FailureCategory != RepairFailureExecution {
		t.Fatalf("expected RepairFailureExecution for a non-fingerprint error string, got %v", audit.FailureCategory)
	}
}

func TestBuildRPMRepairAuditEventMarksSuccessAsNoFailure(t *testing.T) {
	execution := ApprovalExecutionResult{
		Decision: ApprovalExecutionExecuted,
		Action:   RepairAction{ID: "rpm-hashicorp-dnf_repo_gpg_failure", ProfileID: "hashicorp"},
		RepairResult: RepairResult{
			Attempted: true,
			Applied:   true,
		},
	}

	audit := BuildRPMRepairAuditEvent(execution, execution.RepairResult.Snapshot.CreatedAt)

	if audit.FailureCategory != RepairFailureNone {
		t.Fatalf("expected RepairFailureNone for a successful apply, got %v", audit.FailureCategory)
	}
}

func TestRPMRepairAuditPathDefaultsWhenEnvUnset(t *testing.T) {
	os.Unsetenv(rpmRepairAuditPathEnv)

	if got := RPMRepairAuditPath(); got != defaultRPMRepairAuditPath {
		t.Fatalf("expected default audit path %q, got %q", defaultRPMRepairAuditPath, got)
	}
}
