package repohealer

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type bubblewrapExecutor struct {
	t          *testing.T
	targetRoot string
	stubDir    string
	commands   []string
	outputs    []string
}

func (e *bubblewrapExecutor) Run(command string) (string, error) {
	e.t.Helper()
	e.commands = append(e.commands, "RUN: "+command)
	return e.runSandboxScript(command)
}

func (e *bubblewrapExecutor) RunSudo(script string) (string, error) {
	e.t.Helper()
	e.commands = append(e.commands, "SUDO: "+script)
	return e.runSandboxScript(script)
}

func (e *bubblewrapExecutor) RunSudoWithLabel(
	script string,
	label string,
) (string, error) {
	e.t.Helper()
	e.commands = append(e.commands, "SUDO_LABEL["+label+"]: "+script)
	return e.runSandboxScript(script)
}

func (e *bubblewrapExecutor) runSandboxScript(script string) (string, error) {
	e.t.Helper()

	cmd := exec.Command(
		"bwrap",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-net",
		"--uid", "0",
		"--gid", "0",
		"--bind", e.targetRoot, "/",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind", "/lib64", "/lib64",
		"--ro-bind", e.stubDir, "/cross-suite-test-bin",
		"--proc", "/proc",
		"--dev", "/dev",
		"--setenv", "PATH", "/cross-suite-test-bin:/usr/bin:/bin",
		"--",
		"bash", "-c", script,
	)

	output, err := cmd.CombinedOutput()
	e.outputs = append(e.outputs, string(output))
	return string(output), err
}

func writeExecutableTestStub(
	t *testing.T,
	dir string,
	name string,
	script string,
) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestDeb822RepairVerificationFailureRollsBackInBubblewrap(t *testing.T) {
	targetRoot := t.TempDir()
	stubDir := t.TempDir()

	writeTestFile(
		t,
		filepath.Join(targetRoot, "etc", "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"),
		0o644,
	)
	writeTestFile(
		t,
		filepath.Join(targetRoot, "etc", "group"),
		[]byte("root:x:0:\n"),
		0o644,
	)

	sourcePath := filepath.Join(
		targetRoot,
		"etc",
		"apt",
		"sources.list.d",
		"docker.sources",
	)
	keyringPath := filepath.Join(
		targetRoot,
		"etc",
		"apt",
		"keyrings",
		"docker.gpg",
	)

	originalSource := []byte(`Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`)
	originalKeyring := []byte("original-test-keyring\n")

	writeTestFile(t, sourcePath, originalSource, 0o640)
	writeTestFile(t, keyringPath, originalKeyring, 0o600)

	sourceBefore, sourceModeBefore := readTestFile(t, sourcePath)
	keyringBefore, keyringModeBefore := readTestFile(t, keyringPath)

	writeExecutableTestStub(t, stubDir, "curl", `#!/bin/bash
set -eu
output=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		-o)
			output="$2"
			shift 2
			;;
		*)
			shift
			;;
	esac
done
test -n "$output"
printf '%s\n' 'test-vendor-asc' > "$output"
`)

	writeExecutableTestStub(t, stubDir, "gpg", `#!/bin/bash
set -eu
if [ "$1" = "--show-keys" ]; then
	printf 'fpr:::::::::%s:\n' '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
	exit 0
fi

output=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		--output)
			output="$2"
			shift 2
			;;
		*)
			shift
			;;
	esac
done
test -n "$output"
printf '%s\n' 'test-vendor-gpg' > "$output"
`)

	writeExecutableTestStub(t, stubDir, "awk", `#!/bin/bash
set -eu
while IFS= read -r line; do
	case "$line" in
		fpr:*)
			value="$(printf '%s\n' "$line" | cut -d: -f10)"
			if [ -n "$value" ]; then
				printf '%s\n' "$value"
			fi
			;;
	esac
done
`)

	request := validDockerDeb822ExecutionRequest(t)
	fixedTime := time.Date(2026, time.September, 12, 1, 2, 3, 456, time.UTC)

	exec := &bubblewrapExecutor{
		t:          t,
		targetRoot: targetRoot,
		stubDir:    stubDir,
	}

	got := applyDeb822RepairExecutionWithOptions(
		exec,
		request,
		deb822RepairExecutionOptions{
			snapshotRoot:       "/var/lib/cross-suite/snapshots",
			temporaryRoot:      "/var/tmp",
			verificationScript: "printf 'forced verification failure\\n'; exit 99",
			now: func() time.Time {
				return fixedTime
			},
		},
	)

	if got.Applied {
		t.Fatalf("verification-failed repair unexpectedly applied: %#v", got)
	}
	if !got.RolledBack {
		t.Fatalf("verification-failed repair did not roll back: %#v", got)
	}
	if got.Error == nil || !strings.Contains(got.Error.Error(), "verification failed") {
		t.Fatalf("error = %v, want verification failure", got.Error)
	}
	if !got.Snapshot.Created {
		t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
	}
	if len(exec.outputs) < 3 {
		t.Fatalf(
			"sandbox output count = %d, want at least lock, snapshot, and mutation outputs",
			len(exec.outputs),
		)
	}
	if !strings.Contains(
		exec.outputs[2],
		"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=",
	) {
		t.Fatalf(
			"mutation did not report the applied marker:\n%s",
			exec.outputs[2],
		)
	}

	sourceAfter, sourceModeAfter := readTestFile(t, sourcePath)
	keyringAfter, keyringModeAfter := readTestFile(t, keyringPath)

	if !bytes.Equal(sourceAfter, sourceBefore) {
		t.Fatalf(
			"source after rollback = %q, want %q",
			sourceAfter,
			sourceBefore,
		)
	}
	if sourceModeAfter != sourceModeBefore {
		t.Fatalf(
			"source mode after rollback = %o, want %o",
			sourceModeAfter,
			sourceModeBefore,
		)
	}
	if !bytes.Equal(keyringAfter, keyringBefore) {
		t.Fatalf(
			"keyring after rollback = %q, want %q",
			keyringAfter,
			keyringBefore,
		)
	}
	if keyringModeAfter != keyringModeBefore {
		t.Fatalf(
			"keyring mode after rollback = %o, want %o",
			keyringModeAfter,
			keyringModeBefore,
		)
	}

	snapshotRoot := filepath.Join(
		targetRoot,
		"var",
		"lib",
		"cross-suite",
		"snapshots",
	)
	if _, err := os.Stat(snapshotRoot); err != nil {
		t.Fatalf("snapshot root was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(
		targetRoot,
		"var",
		"tmp",
	)); err != nil {
		t.Fatalf("temporary workspace root was not created: %v", err)
	}

	if len(exec.commands) != 5 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, verification, rollback: %#v",
			len(exec.commands),
			exec.commands,
		)
	}
	if !strings.Contains(
		exec.commands[4],
		"sha256sum --strict -c checksums.sha256",
	) {
		t.Fatalf(
			"rollback did not verify snapshot checksums:\n%s",
			exec.commands[4],
		)
	}

	for _, command := range exec.commands {
		if strings.Contains(command, targetRoot) {
			t.Fatalf("generated transaction command leaked host target root:\n%s", command)
		}
	}
}
