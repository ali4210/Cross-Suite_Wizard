package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestReadAndPrepareDeb822RepairBuildsPreparedPayload(t *testing.T) {
	action := dockerDeb822RepairAction()
	profile := dockerDeb822Profile(t)

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(validDockerDeb822Document()),
		},
	}

	got, err := ReadAndPrepareDeb822Repair(exec, action, profile)
	if err != nil {
		t.Fatalf("ReadAndPrepareDeb822Repair() error = %v", err)
	}

	if got.ProfileID != profile.ID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, profile.ID)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.KeyringPath != profile.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, profile.KeyringPath)
	}
	if got.RenderedSource == "" {
		t.Fatal("prepared payload must contain a rendered Deb822 source")
	}
	if len(got.SnapshotTargets) != 2 {
		t.Fatalf(
			"snapshot target count = %d, want 2",
			len(got.SnapshotTargets),
		)
	}

	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestReadAndPrepareDeb822RepairRejectsInvalidActionBeforeReading(t *testing.T) {
	action := dockerDeb822RepairAction()
	action.SourceFile = "/tmp/docker.sources"

	exec := &fakeExecutor{}

	_, err := ReadAndPrepareDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)
	if err == nil {
		t.Fatal("invalid action unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "is outside /etc/apt/sources.list.d") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exec.commands) != 0 {
		t.Fatalf(
			"invalid action must not issue reader commands: %v",
			exec.commands,
		)
	}
}

func TestReadAndPrepareDeb822RepairRejectsReaderFailure(t *testing.T) {
	action := dockerDeb822RepairAction()

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderError("symlink"),
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 11"),
		},
	}

	got, err := ReadAndPrepareDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)
	if err == nil {
		t.Fatal("reader rejection unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "read blocked: symlink") {
		t.Fatalf("unexpected reader error: %v", err)
	}
	assertEmptyPreparedDeb822Repair(t, got)
	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestReadAndPrepareDeb822RepairRejectsUnsafeDocumentAfterReading(t *testing.T) {
	action := dockerDeb822RepairAction()

	document := validDockerDeb822Document() + `
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg
`

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(document),
		},
	}

	got, err := ReadAndPrepareDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)
	if err == nil {
		t.Fatal("multi-stanza document unexpectedly prepared")
	}
	if !strings.Contains(err.Error(), "contains 2 non-comment stanzas") {
		t.Fatalf("unexpected document error: %v", err)
	}
	assertEmptyPreparedDeb822Repair(t, got)
	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestReadAndPrepareDeb822RepairRejectsUnsupportedTargetAfterReading(t *testing.T) {
	action := dockerDeb822RepairAction()
	action.Target.Distribution = "ubuntu"
	action.Target.Codename = "noble"

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(validDockerDeb822Document()),
		},
	}

	got, err := ReadAndPrepareDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)
	if err == nil {
		t.Fatal("unsupported target unexpectedly prepared")
	}
	if !strings.Contains(err.Error(), "unable to render source") {
		t.Fatalf("unexpected render error: %v", err)
	}
	assertEmptyPreparedDeb822Repair(t, got)
	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func assertEmptyPreparedDeb822Repair(
	t *testing.T,
	got PreparedDeb822Repair,
) {
	t.Helper()

	if got.ProfileID != "" ||
		got.SourceFile != "" ||
		got.KeyringPath != "" ||
		got.RenderedSource != "" ||
		len(got.SnapshotTargets) != 0 {
		t.Fatalf(
			"blocked flow must return an empty prepared payload, got %#v",
			got,
		)
	}
}

func assertDeb822ReadOnlyCommand(
	t *testing.T,
	commands []string,
	wantCount int,
) {
	t.Helper()

	if len(commands) != wantCount {
		t.Fatalf(
			"command count = %d, want %d: %v",
			len(commands),
			wantCount,
			commands,
		)
	}

	for _, command := range commands {
		for _, forbidden := range []string{
			"apt-get update",
			"curl ",
			"gpg ",
			"mv ",
			"rm -f",
			"rm -rf",
			"chmod ",
			"chown ",
			"install ",
			"CreateAPTFileSnapshot",
			"RestoreAPTFileSnapshot",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf(
					"read-and-prepare flow must not contain %q:\n%s",
					forbidden,
					command,
				)
			}
		}

		if !strings.Contains(
			command,
			"Reading Approved Deb822 APT Source",
		) {
			t.Fatalf(
				"expected approved Deb822 reader command, got:\n%s",
				command,
			)
		}
	}
}
