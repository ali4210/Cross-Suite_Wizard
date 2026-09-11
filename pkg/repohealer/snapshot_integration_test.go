package repohealer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type localScriptExecutor struct {
	t        *testing.T
	commands []string
}

func (e *localScriptExecutor) Run(command string) (string, error) {
	e.commands = append(e.commands, "RUN: "+command)
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *localScriptExecutor) RunSudo(script string) (string, error) {
	e.commands = append(e.commands, "LOCAL_SUDO: "+script)
	cmd := exec.Command("bash", "-c", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *localScriptExecutor) RunSudoWithLabel(script, label string) (string, error) {
	e.commands = append(e.commands, "LOCAL_SUDO_LABEL["+label+"]: "+script)
	cmd := exec.Command("bash", "-c", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func writeTestFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%q): %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) ([]byte, os.FileMode) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}

	return content, info.Mode().Perm()
}

func TestAPTSnapshotRestoreRoundTripOnTemporaryFilesystem(t *testing.T) {
	root := t.TempDir()
	snapshotRoot := filepath.Join(root, "snapshots")

	sourceFile := filepath.Join(
		root,
		"etc",
		"apt",
		"sources.list.d",
		"docker.list",
	)
	keyringFile := filepath.Join(
		root,
		"etc",
		"apt",
		"keyrings",
		"docker.gpg",
	)

	originalSource := []byte(
		"deb [arch=amd64 signed-by=/old/docker.gpg] https://old.example.invalid stable stable\n",
	)
	originalKeyring := []byte("original-test-keyring-bytes\n")

	writeTestFile(t, sourceFile, originalSource, 0o640)
	writeTestFile(t, keyringFile, originalKeyring, 0o600)

	exec := &localScriptExecutor{t: t}
	fixedTime := time.Date(2026, time.September, 11, 0, 0, 0, 0, time.UTC)

	snapshot, err := createAPTFileSnapshotAtRoot(
		exec,
		[]string{sourceFile, keyringFile},
		snapshotRoot,
		fixedTime,
		"apt-integration-roundtrip",
	)
	if err != nil {
		t.Fatalf("createAPTFileSnapshotAtRoot() error = %v", err)
	}
	if !snapshot.Created {
		t.Fatal("expected created snapshot")
	}

	writeTestFile(
		t,
		sourceFile,
		[]byte("deb [arch=amd64 signed-by=/new/docker.gpg] https://new.example.invalid bookworm stable\n"),
		0o644,
	)
	writeTestFile(t, keyringFile, []byte("mutated-test-keyring-bytes\n"), 0o644)

	if err := restoreAPTFileSnapshot(
		exec,
		snapshot,
		[]string{sourceFile, keyringFile},
		false,
	); err != nil {
		t.Fatalf("restoreAPTFileSnapshot() error = %v", err)
	}

	gotSource, gotSourceMode := readTestFile(t, sourceFile)
	if string(gotSource) != string(originalSource) {
		t.Fatalf("source content after restore = %q, want %q", gotSource, originalSource)
	}
	if gotSourceMode != 0o640 {
		t.Fatalf("source mode after restore = %o, want 640", gotSourceMode)
	}

	gotKeyring, gotKeyringMode := readTestFile(t, keyringFile)
	if string(gotKeyring) != string(originalKeyring) {
		t.Fatalf("keyring content after restore = %q, want %q", gotKeyring, originalKeyring)
	}
	if gotKeyringMode != 0o600 {
		t.Fatalf("keyring mode after restore = %o, want 600", gotKeyringMode)
	}

	if len(exec.commands) != 2 {
		t.Fatalf("expected snapshot and restore commands, got %d: %v", len(exec.commands), exec.commands)
	}

	if _, err := os.Stat(filepath.Join(snapshot.Path, "checksums.sha256")); err != nil {
		t.Fatalf("expected checksum manifest: %v", err)
	}
}

func TestAPTSnapshotRestoreRemovesOriginallyAbsentFileOnTemporaryFilesystem(t *testing.T) {
	root := t.TempDir()
	snapshotRoot := filepath.Join(root, "snapshots")

	presentFile := filepath.Join(
		root,
		"etc",
		"apt",
		"sources.list.d",
		"docker.list",
	)
	originallyAbsentFile := filepath.Join(
		root,
		"etc",
		"apt",
		"keyrings",
		"docker.gpg",
	)

	originalSource := []byte("deb https://old.example.invalid stable stable\n")
	writeTestFile(t, presentFile, originalSource, 0o640)

	exec := &localScriptExecutor{t: t}
	fixedTime := time.Date(2026, time.September, 11, 0, 0, 1, 0, time.UTC)

	snapshot, err := createAPTFileSnapshotAtRoot(
		exec,
		[]string{presentFile, originallyAbsentFile},
		snapshotRoot,
		fixedTime,
		"apt-integration-absent",
	)
	if err != nil {
		t.Fatalf("createAPTFileSnapshotAtRoot() error = %v", err)
	}

	writeTestFile(t, presentFile, []byte("mutated source\n"), 0o644)
	writeTestFile(t, originallyAbsentFile, []byte("new keyring\n"), 0o644)

	if err := restoreAPTFileSnapshot(
		exec,
		snapshot,
		[]string{presentFile, originallyAbsentFile},
		false,
	); err != nil {
		t.Fatalf("restoreAPTFileSnapshot() error = %v", err)
	}

	gotSource, gotMode := readTestFile(t, presentFile)
	if string(gotSource) != string(originalSource) {
		t.Fatalf("present file after restore = %q, want %q", gotSource, originalSource)
	}
	if gotMode != 0o640 {
		t.Fatalf("present file mode after restore = %o, want 640", gotMode)
	}

	if _, err := os.Stat(originallyAbsentFile); !os.IsNotExist(err) {
		t.Fatalf("originally absent file must be removed by rollback, stat error = %v", err)
	}
}

func TestAPTSnapshotRestoreRejectsTamperedTemporarySnapshot(t *testing.T) {
	root := t.TempDir()
	snapshotRoot := filepath.Join(root, "snapshots")
	target := filepath.Join(root, "etc", "apt", "sources.list.d", "docker.list")

	original := []byte("original source\n")
	writeTestFile(t, target, original, 0o640)

	exec := &localScriptExecutor{t: t}
	fixedTime := time.Date(2026, time.September, 11, 0, 0, 2, 0, time.UTC)

	snapshot, err := createAPTFileSnapshotAtRoot(
		exec,
		[]string{target},
		snapshotRoot,
		fixedTime,
		"apt-integration-tamper",
	)
	if err != nil {
		t.Fatalf("createAPTFileSnapshotAtRoot() error = %v", err)
	}

	writeTestFile(t, target, []byte("mutated live source\n"), 0o644)

	relative := strings.TrimPrefix(target, "/")
	snapshotContent := filepath.Join(
		snapshot.Path,
		"files",
		relative+".content",
	)
	if err := os.WriteFile(snapshotContent, []byte("tampered snapshot bytes\n"), 0o600); err != nil {
		t.Fatalf("tamper snapshot content: %v", err)
	}

	err = restoreAPTFileSnapshot(exec, snapshot, []string{target}, false)
	if err == nil {
		t.Fatal("expected checksum validation to reject tampered snapshot")
	}

	got, mode := readTestFile(t, target)
	if string(got) != "mutated live source\n" {
		t.Fatalf("target must remain unchanged after rejected rollback, got %q", got)
	}
	if mode != 0o644 {
		t.Fatalf("target mode must remain unchanged after rejected rollback, got %o", mode)
	}
}
