package repohealer

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type hashicorpAPTListRepairExecutionPanicExecutor struct{}

func (hashicorpAPTListRepairExecutionPanicExecutor) Run(string) (string, error) {
	panic("unexpected Run call")
}

func (hashicorpAPTListRepairExecutionPanicExecutor) RunSudo(string) (string, error) {
	panic("unexpected RunSudo call")
}

func (hashicorpAPTListRepairExecutionPanicExecutor) RunSudoWithLabel(
	string,
	string,
) (string, error) {
	panic("unexpected RunSudoWithLabel call")
}

type hashiCorpAPTListRepairExecutionFakeResponse struct {
	output string
	err    error
}

type hashiCorpAPTListRepairExecutionFakeExecutor struct {
	labeledOutputs []hashiCorpAPTListRepairExecutionFakeResponse
	sudoOutputs    []hashiCorpAPTListRepairExecutionFakeResponse
	labeledCalls   int
	sudoCalls      int
	scripts        []string
	labels         []string
	sudoScripts    []string
}

func (f *hashiCorpAPTListRepairExecutionFakeExecutor) Run(
	command string,
) (string, error) {
	return "", fmt.Errorf("unexpected Run call: %s", command)
}

func (f *hashiCorpAPTListRepairExecutionFakeExecutor) RunSudo(
	script string,
) (string, error) {
	if f.sudoCalls >= len(f.sudoOutputs) {
		return "", fmt.Errorf("unexpected RunSudo call %d", f.sudoCalls+1)
	}

	response := f.sudoOutputs[f.sudoCalls]
	f.sudoCalls++
	f.sudoScripts = append(f.sudoScripts, script)

	return response.output, response.err
}

func (f *hashiCorpAPTListRepairExecutionFakeExecutor) RunSudoWithLabel(
	script string,
	label string,
) (string, error) {
	if f.labeledCalls >= len(f.labeledOutputs) {
		return "", fmt.Errorf(
			"unexpected RunSudoWithLabel call %d",
			f.labeledCalls+1,
		)
	}

	response := f.labeledOutputs[f.labeledCalls]
	f.labeledCalls++
	f.scripts = append(f.scripts, script)
	f.labels = append(f.labels, label)

	return response.output, response.err
}

func TestExecuteHashiCorpAPTListRepairBlocksInvalidRequestWithoutExecution(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	request.KeyringPath = "/tmp/not-approved.gpg"

	got := ExecuteHashiCorpAPTListRepair(
		hashicorpAPTListRepairExecutionPanicExecutor{},
		request,
		HashiCorpAPTListRepairPreflight{},
	)

	if got.Status != HashiCorpAPTListRepairExecutionBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(strings.ToLower(got.Reason), "request") {
		t.Fatalf("reason = %q, want request validation failure", got.Reason)
	}
}

func TestExecuteHashiCorpAPTListRepairBlocksUnreadyPreflightWithoutExecution(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	got := ExecuteHashiCorpAPTListRepair(
		hashicorpAPTListRepairExecutionPanicExecutor{},
		request,
		HashiCorpAPTListRepairPreflight{
			Request: request,
			Ready:   false,
			Reason:  "APT/dpkg lock is active",
		},
	)

	if got.Status != HashiCorpAPTListRepairExecutionBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(got.Reason, "preflight is not ready") {
		t.Fatalf("reason = %q, want preflight block", got.Reason)
	}
}

func TestExecuteHashiCorpAPTListRepairBlocksMismatchedPreflightWithoutExecution(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	mismatched := request
	mismatched.SourceLine++

	got := ExecuteHashiCorpAPTListRepair(
		hashicorpAPTListRepairExecutionPanicExecutor{},
		request,
		HashiCorpAPTListRepairPreflight{
			Request: mismatched,
			Ready:   true,
		},
	)

	if got.Status != HashiCorpAPTListRepairExecutionBlocked {
		t.Fatalf("status = %q, want blocked", got.Status)
	}
	if !strings.Contains(got.Reason, "does not match") {
		t.Fatalf("reason = %q, want request-binding failure", got.Reason)
	}
}

func TestExecuteHashiCorpAPTListRepairReprobesBeforeAnyMutation(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairPreflightProbeFakeExecutor{
		output: readyHashiCorpAPTListRepairPreflightProbeOutputWithPresentKeyring(),
	}

	got := ExecuteHashiCorpAPTListRepair(
		exec,
		request,
		HashiCorpAPTListRepairPreflight{
			Request:      request,
			Ready:        true,
			DoctorReport: blockedHashiCorpAPTListRepairDoctorReport(t),
		},
	)

	if exec.calls != 1 {
		t.Fatalf("preflight probe calls = %d, want 1", exec.calls)
	}
	if exec.label != hashicorpAPTListRepairPreflightProbeLabel {
		t.Fatalf(
			"label = %q, want %q",
			exec.label,
			hashicorpAPTListRepairPreflightProbeLabel,
		)
	}
	if got.Status != HashiCorpAPTListRepairExecutionBlocked {
		t.Fatalf("status = %q, want blocked until mutation is implemented", got.Status)
	}
	if got.Reason != "HashiCorp APT-list repair execution is not implemented" {
		t.Fatalf("reason = %q", got.Reason)
	}
}

func TestBuildHashiCorpAPTListRepairExecutionScriptRestrictsWritesToKeyring(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairExecutionScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairExecutionScript() error = %v",
			err,
		)
	}

	for _, want := range []string{
		request.KeyURL,
		request.KeyringPath,
		request.ExpectedFingerprint,
		`curl -fsSL --proto '=https' --tlsv1.2`,
		"gpg --show-keys --with-colons --fingerprint",
		"gpg --dearmor --yes",
		`mktemp "$KEYRING_DIR/`,
		"install -o root -g root -m 0644",
		`mv -f "$KEYRING_TMP" "$KEYRING_PATH"`,
		"HASHICORP_APT_LIST_REPAIR_APPLIED|",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not contain %q: %q", want, script)
		}
	}

	for _, want := range []string{
		`TEMP_DIR="$(mktemp -d /var/tmp/cross-suite-hashicorp-apt-list-repair.XXXXXX)"`,
		`chmod 0700 "$TEMP_DIR"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not contain %q: %q", want, script)
		}
	}

	if strings.Contains(
		script,
		`TEMP_DIR="/var/tmp/cross-suite-hashicorp-apt-list-repair-`,
	) {
		t.Fatalf(
			"script must not use a predictable fixed temporary directory: %q",
			script,
		)
	}

	for _, forbidden := range []string{
		"SOURCE_FILE=",
		"SOURCE_TMP=",
		request.SourceFile,
		"RENDERED_SOURCE",
		`mv -f "$SOURCE_TMP"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf(
				"script must not include source-file mutation material %q: %q",
				forbidden,
				script,
			)
		}
	}

	if strings.Count(script, `mv -f "$KEYRING_TMP" "$KEYRING_PATH"`) != 1 {
		t.Fatalf(
			"keyring atomic replacement count = %d, want 1: %q",
			strings.Count(script, `mv -f "$KEYRING_TMP" "$KEYRING_PATH"`),
			script,
		)
	}
}

func TestHasHashiCorpAPTListRepairAppliedMarker(t *testing.T) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name: "Valid marker",
			output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
				request.ExpectedFingerprint,
			want: true,
		},
		{
			name: "Marker surrounded by output",
			output: "download complete\n" +
				"HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
				request.ExpectedFingerprint +
				"\nverification pending",
			want: true,
		},
		{
			name: "Wrong profile",
			output: "HASHICORP_APT_LIST_REPAIR_APPLIED|docker-ce|fingerprint=" +
				request.ExpectedFingerprint,
			want: false,
		},
		{
			name: "Wrong fingerprint",
			output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			want: false,
		},
		{
			name:   "Missing marker",
			output: "keyring written",
			want:   false,
		},
		{
			name:   "Malformed marker",
			output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp",
			want:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hasHashiCorpAPTListRepairAppliedMarker(test.output, request)
			if got != test.want {
				t.Fatalf(
					"hasHashiCorpAPTListRepairAppliedMarker(%q) = %t, want %t",
					test.output,
					got,
					test.want,
				)
			}
		})
	}
}

func TestApplyHashiCorpAPTListRepairExecutionRejectsMissingSuccessMarker(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairExecutionFakeExecutor{
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "downloaded key material but no success marker",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
		},
	}

	got := applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	if got.Status != HashiCorpAPTListRepairExecutionFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.Attempted {
		t.Fatalf("attempted = false, want true")
	}
	if got.Applied {
		t.Fatalf("applied = true, want false")
	}
	if !strings.Contains(got.Reason, "valid success marker") {
		t.Fatalf("reason = %q, want missing-marker failure", got.Reason)
	}
	if exec.labeledCalls != 1 {
		t.Fatalf(
			"mutation executor calls = %d, want 1",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 1 {
		t.Fatalf(
			"snapshot executor calls = %d, want 1",
			exec.sudoCalls,
		)
	}
}

func TestApplyHashiCorpAPTListRepairExecutionRollsBackAfterMissingSuccessMarker(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairExecutionFakeExecutor{
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "keyring replacement returned no success marker",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
			{},
		},
	}

	got := applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	if got.Status != HashiCorpAPTListRepairExecutionFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if got.Applied {
		t.Fatal("applied = true, want false")
	}
	if !got.RolledBack {
		t.Fatal("rolledBack = false, want true")
	}
	if exec.sudoCalls != 2 {
		t.Fatalf("sudo calls = %d, want 2 (snapshot + rollback)", exec.sudoCalls)
	}
	if len(exec.sudoScripts) != 2 {
		t.Fatalf("sudo scripts = %d, want 2", len(exec.sudoScripts))
	}
	if !strings.Contains(exec.sudoScripts[0], request.KeyringPath) {
		t.Fatalf(
			"snapshot script does not target keyring %q: %q",
			request.KeyringPath,
			exec.sudoScripts[0],
		)
	}
	if strings.Contains(exec.sudoScripts[0], request.SourceFile) {
		t.Fatalf(
			"snapshot script must not target source file %q: %q",
			request.SourceFile,
			exec.sudoScripts[0],
		)
	}
	if !strings.Contains(exec.sudoScripts[1], request.KeyringPath) {
		t.Fatalf(
			"rollback script does not target keyring %q: %q",
			request.KeyringPath,
			exec.sudoScripts[1],
		)
	}
	if strings.Contains(exec.sudoScripts[1], request.SourceFile) {
		t.Fatalf(
			"rollback script must not target source file %q: %q",
			request.SourceFile,
			exec.sudoScripts[1],
		)
	}
}

func TestApplyHashiCorpAPTListRepairExecutionRollsBackOnAPTVerificationFailure(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairExecutionFakeExecutor{
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
					request.ExpectedFingerprint,
			},
			{
				output: "W: GPG error: https://apt.releases.hashicorp.com bookworm InRelease: NO_PUBKEY FC9CA96ACA026560\n" +
					"W: Failed to fetch https://apt.releases.hashicorp.com/dists/bookworm/InRelease",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
			{},
		},
	}

	got := applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	if got.Status != HashiCorpAPTListRepairExecutionFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if got.Applied {
		t.Fatal("applied = true, want false")
	}
	if !got.RolledBack {
		t.Fatal("rolledBack = false, want true")
	}
	if !strings.Contains(strings.ToLower(got.Reason), "verification") {
		t.Fatalf("reason = %q, want verification failure", got.Reason)
	}
	if !strings.Contains(got.VerificationOut, "NO_PUBKEY") {
		t.Fatalf(
			"verification output = %q, want HashiCorp NO_PUBKEY diagnostics",
			got.VerificationOut,
		)
	}
	if exec.labeledCalls != 2 {
		t.Fatalf(
			"labeled calls = %d, want 2 (mutation + verification)",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 2 {
		t.Fatalf(
			"sudo calls = %d, want 2 (snapshot + rollback)",
			exec.sudoCalls,
		)
	}
	if len(exec.scripts) != 2 {
		t.Fatalf("labeled scripts = %d, want 2", len(exec.scripts))
	}
	if !strings.Contains(exec.scripts[1], "apt-get update") {
		t.Fatalf(
			"verification script must run apt-get update: %q",
			exec.scripts[1],
		)
	}
}

func TestApplyHashiCorpAPTListRepairExecutionAppliesAfterAPTVerification(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairExecutionFakeExecutor{
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
					request.ExpectedFingerprint,
			},
			{
				output: "Hit:1 https://apt.releases.hashicorp.com bookworm InRelease\n" +
					"HASHICORP_APT_LIST_REPAIR_VERIFIED|host=apt.releases.hashicorp.com|exit=0",
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
		},
	}

	got := applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	if got.Status != HashiCorpAPTListRepairExecutionApplied {
		t.Fatalf("status = %q, want applied", got.Status)
	}
	if !got.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if !got.Applied {
		t.Fatal("applied = false, want true")
	}
	if got.RolledBack {
		t.Fatal("rolledBack = true, want false")
	}
	if !strings.Contains(
		got.VerificationOut,
		"HASHICORP_APT_LIST_REPAIR_VERIFIED|host=apt.releases.hashicorp.com|exit=0",
	) {
		t.Fatalf(
			"verification output = %q, want successful verification marker",
			got.VerificationOut,
		)
	}
	if exec.labeledCalls != 2 {
		t.Fatalf(
			"labeled calls = %d, want 2 (mutation + verification)",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 1 {
		t.Fatalf(
			"sudo calls = %d, want 1 (snapshot only)",
			exec.sudoCalls,
		)
	}
	if len(exec.scripts) != 2 {
		t.Fatalf("labeled scripts = %d, want 2", len(exec.scripts))
	}
	if !strings.Contains(exec.scripts[1], "apt-get update") {
		t.Fatalf(
			"verification script must run apt-get update: %q",
			exec.scripts[1],
		)
	}
}

func TestApplyHashiCorpAPTListRepairExecutionRollsBackOnAPTVerificationCommandError(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	exec := &hashiCorpAPTListRepairExecutionFakeExecutor{
		labeledOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{
				output: "HASHICORP_APT_LIST_REPAIR_APPLIED|hashicorp|fingerprint=" +
					request.ExpectedFingerprint,
			},
			{
				err: errors.New("apt-get update could not be started"),
			},
		},
		sudoOutputs: []hashiCorpAPTListRepairExecutionFakeResponse{
			{},
			{},
		},
	}

	got := applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		blockedHashiCorpAPTListRepairDoctorReport(t),
	)

	if got.Status != HashiCorpAPTListRepairExecutionFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !got.Attempted {
		t.Fatal("attempted = false, want true")
	}
	if got.Applied {
		t.Fatal("applied = true, want false")
	}
	if !got.RolledBack {
		t.Fatal("rolledBack = false, want true")
	}
	if !strings.Contains(strings.ToLower(got.Reason), "verification failed") {
		t.Fatalf("reason = %q, want verification failure", got.Reason)
	}
	if got.VerificationOut != "" {
		t.Fatalf(
			"verification output = %q, want empty output on command error",
			got.VerificationOut,
		)
	}
	if exec.labeledCalls != 2 {
		t.Fatalf(
			"labeled calls = %d, want 2 (mutation + verification)",
			exec.labeledCalls,
		)
	}
	if exec.sudoCalls != 2 {
		t.Fatalf(
			"sudo calls = %d, want 2 (snapshot + rollback)",
			exec.sudoCalls,
		)
	}
}
