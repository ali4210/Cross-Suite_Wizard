package repohealer

import (
	"errors"
	"strings"
	"testing"
)

type hashiCorpAPTListRepairPreflightProbeFakeExecutor struct {
	output string
	err    error
	calls  int
	script string
	label  string
}

func (f *hashiCorpAPTListRepairPreflightProbeFakeExecutor) RunSudoWithLabel(
	script string,
	label string,
) (string, error) {
	f.calls++
	f.script = script
	f.label = label
	return f.output, f.err
}

func (f *hashiCorpAPTListRepairPreflightProbeFakeExecutor) Run(
	command string,
) (string, error) {
	return "", errors.New("unexpected Run call: " + command)
}

func (f *hashiCorpAPTListRepairPreflightProbeFakeExecutor) RunSudo(
	script string,
) (string, error) {
	return "", errors.New("unexpected RunSudo call")
}

func TestProbeHashiCorpAPTListRepairPreflightRejectsInvalidRequestBeforeExecution(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	request.KeyringPath = "/tmp/other.gpg"

	exec := &hashiCorpAPTListRepairPreflightProbeFakeExecutor{
		output: readyHashiCorpAPTListRepairPreflightProbeOutput(),
	}

	_, err := ProbeHashiCorpAPTListRepairPreflight(exec, request)
	if err == nil {
		t.Fatal("ProbeHashiCorpAPTListRepairPreflight() unexpectedly succeeded")
	}
	if exec.calls != 0 {
		t.Fatalf("executor calls = %d, want 0", exec.calls)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "request") {
		t.Fatalf("error = %q, want it to contain request", err)
	}
}

func TestProbeHashiCorpAPTListRepairPreflightRunsLabeledReadOnlyProbe(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	exec := &hashiCorpAPTListRepairPreflightProbeFakeExecutor{
		output: readyHashiCorpAPTListRepairPreflightProbeOutput(),
	}

	got, err := ProbeHashiCorpAPTListRepairPreflight(exec, request)
	if err != nil {
		t.Fatalf("ProbeHashiCorpAPTListRepairPreflight() error = %v", err)
	}

	if got.Source.State != HashiCorpAPTListRepairPreflightFilePresent {
		t.Fatalf("source = %#v", got.Source)
	}
	if got.Keyring.State != HashiCorpAPTListRepairPreflightFileMissing {
		t.Fatalf("keyring = %#v", got.Keyring)
	}
	if exec.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", exec.calls)
	}
	if exec.label != hashicorpAPTListRepairPreflightProbeLabel {
		t.Fatalf(
			"label = %q, want %q",
			exec.label,
			hashicorpAPTListRepairPreflightProbeLabel,
		)
	}
	if !strings.Contains(exec.script, request.SourceFile) {
		t.Fatalf("script does not bind source file %q", request.SourceFile)
	}
	if !strings.Contains(exec.script, request.KeyringPath) {
		t.Fatalf("script does not bind keyring path %q", request.KeyringPath)
	}
	if strings.Contains(exec.script, "apt-get update") ||
		strings.Contains(exec.script, "curl ") ||
		strings.Contains(exec.script, "wget ") ||
		strings.Contains(exec.script, "gpg --") ||
		strings.Contains(exec.script, " install ") ||
		strings.Contains(exec.script, " mv ") {
		t.Fatalf("probe script contains a forbidden mutation/download command: %q", exec.script)
	}
}

func TestProbeHashiCorpAPTListRepairPreflightReturnsExecutorAndParseErrors(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	tests := []struct {
		name string
		exec hashiCorpAPTListRepairPreflightProbeFakeExecutor
		want string
	}{
		{
			name: "Executor error",
			exec: hashiCorpAPTListRepairPreflightProbeFakeExecutor{
				err: errors.New("SSH unavailable"),
			},
			want: "probe",
		},
		{
			name: "Malformed output",
			exec: hashiCorpAPTListRepairPreflightProbeFakeExecutor{
				output: "not a probe record",
			},
			want: "probe",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exec := test.exec

			_, err := ProbeHashiCorpAPTListRepairPreflight(
				&exec,
				request,
			)
			if err == nil {
				t.Fatal("ProbeHashiCorpAPTListRepairPreflight() unexpectedly succeeded")
			}
			if exec.calls != 1 {
				t.Fatalf("executor calls = %d, want 1", exec.calls)
			}
			if !strings.Contains(
				strings.ToLower(err.Error()),
				strings.ToLower(test.want),
			) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err,
					test.want,
				)
			}
		})
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptUsesReadOnlyFuserLockCheck(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	for _, want := range []string{
		"command -v fuser",
		"fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock",
		"/var/lib/apt/lists/lock",
		"/var/cache/apt/archives/lock",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not contain %q: %q", want, script)
		}
	}

	if strings.Contains(script, "/proc/locks") {
		t.Fatalf("script must not inspect /proc/locks: %q", script)
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptReportsToolsBeforeFiles(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	toolAt := strings.LastIndex(script, `probe_tool "sha256sum"`)
	sourceAt := strings.LastIndex(script, `probe_file "source"`)

	if toolAt < 0 || sourceAt < 0 {
		t.Fatalf("script is missing required probe calls: %q", script)
	}
	if toolAt > sourceAt {
		t.Fatalf(
			"sha256sum tool probe occurs after source file probe: %q",
			script,
		)
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptUsesExplicitNoFinalNewlineEmitter(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	if !strings.Contains(script, `printf '%s' "$1"`) {
		t.Fatalf("script must use a controlled emitter: %q", script)
	}
	if !strings.Contains(script, `printf '\n'`) {
		t.Fatalf("script must emit record separators explicitly: %q", script)
	}
	if strings.Contains(script, "emit '\n'") {
		t.Fatalf("script must not use a literal multiline newline emitter: %q", script)
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptGuardsReadOnlyDependencies(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	statCheckAt := strings.LastIndex(
		script,
		`command -v stat >/dev/null 2>&1`,
	)
	sourceProbeAt := strings.LastIndex(
		script,
		`probe_file "source"`,
	)

	if statCheckAt < 0 || sourceProbeAt < 0 {
		t.Fatalf("script must check stat before probing files: %q", script)
	}
	if statCheckAt > sourceProbeAt {
		t.Fatalf("stat availability check occurs after source probing: %q", script)
	}

	if !strings.Contains(script, `owners="$(fuser`) {
		t.Fatalf(
			"script must capture fuser owners for status-aware lock evaluation: %q",
			script,
		)
	}

	if !strings.Contains(script, "status=$?") {
		t.Fatalf(
			"script must capture fuser's exit status for lock evaluation: %q",
			script,
		)
	}

	if !strings.Contains(script, `[ "$status" -eq 0 ] && [ -n "$owners" ]`) {
		t.Fatalf(
			"script must recognize active locks only when fuser reports owners: %q",
			script,
		)
	}

	if !strings.Contains(script, `[ "$status" -eq 1 ] && [ -z "$owners" ]`) {
		t.Fatalf(
			"script must recognize a clear lock state only for fuser status 1 without owners: %q",
			script,
		)
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptHasNoFinalNewlineOperation(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	if !strings.Contains(script, "emitted=0") {
		t.Fatalf("script must initialize emission state: %q", script)
	}
	if !strings.Contains(
		script,
		`if [ "$emitted" -eq 1 ]; then
		printf '\n'
	fi`,
	) {
		t.Fatalf("script must emit separators only before later records: %q", script)
	}

	if !strings.HasSuffix(strings.TrimSpace(script), "probe_lock") {
		t.Fatalf(
			"script must end at the lock probe without a final output operation: %q",
			script,
		)
	}
}

func TestBuildHashiCorpAPTListRepairPreflightProbeScriptFailsClosedOnUncertainFuserResult(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		t.Fatalf(
			"buildHashiCorpAPTListRepairPreflightProbeScript() error = %v",
			err,
		)
	}

	for _, want := range []string{
		"set +e",
		`owners="$(fuser`,
		"status=$?",
		`[ "$status" -eq 0 ] && [ -n "$owners" ]`,
		`[ "$status" -eq 1 ] && [ -z "$owners" ]`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not contain %q: %q", want, script)
		}
	}

	if strings.Contains(
		script,
		"if fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock",
	) {
		t.Fatalf(
			"script must not treat every nonzero fuser exit as a clear lock state: %q",
			script,
		)
	}
}
