package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestInspectApprovedDeb822RepairReturnsReviewablePayload(t *testing.T) {
	action := dockerDeb822RepairAction()
	profile := dockerDeb822Profile(t)

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(validDockerDeb822Document()),
		},
	}

	got := InspectApprovedDeb822Repair(exec, action, profile)

	if !got.Ready {
		t.Fatalf("inspection must be ready, reason: %s", got.BlockReason)
	}
	if got.BlockReason != "" {
		t.Fatalf("ready inspection must not have a block reason: %s", got.BlockReason)
	}
	if got.ActionID != action.ID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, action.ID)
	}
	if got.ProfileID != profile.ID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, profile.ID)
	}
	if got.ProfileName != profile.DisplayName {
		t.Fatalf("profile name = %q, want %q", got.ProfileName, profile.DisplayName)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.KeyringPath != profile.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, profile.KeyringPath)
	}
	if got.RenderedSource == "" {
		t.Fatal("ready inspection must include the rendered replacement source")
	}
	if len(got.SnapshotTargets) != 2 {
		t.Fatalf(
			"snapshot target count = %d, want 2",
			len(got.SnapshotTargets),
		)
	}

	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestInspectApprovedDeb822RepairBlocksInvalidActionWithoutCommands(t *testing.T) {
	action := dockerDeb822RepairAction()
	action.SourceFile = "/tmp/docker.sources"

	exec := &fakeExecutor{}
	got := InspectApprovedDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)

	if got.Ready {
		t.Fatal("invalid action must not produce a ready inspection")
	}
	if !strings.Contains(got.BlockReason, "is outside /etc/apt/sources.list.d") {
		t.Fatalf("unexpected block reason: %s", got.BlockReason)
	}
	if got.RenderedSource != "" || len(got.SnapshotTargets) != 0 {
		t.Fatalf("blocked inspection must not expose a prepared payload: %#v", got)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("invalid action must not run commands: %v", exec.commands)
	}
}

func TestInspectApprovedDeb822RepairBlocksReaderRejection(t *testing.T) {
	action := dockerDeb822RepairAction()

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderError("symlink"),
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 11"),
		},
	}

	got := InspectApprovedDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)

	if got.Ready {
		t.Fatal("symlink reader rejection must block inspection")
	}
	if !strings.Contains(got.BlockReason, "read blocked: symlink") {
		t.Fatalf("unexpected block reason: %s", got.BlockReason)
	}
	if got.RenderedSource != "" || len(got.SnapshotTargets) != 0 {
		t.Fatalf("blocked inspection must not expose a prepared payload: %#v", got)
	}

	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestInspectApprovedDeb822RepairBlocksUnsafeDocument(t *testing.T) {
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

	got := InspectApprovedDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)

	if got.Ready {
		t.Fatal("multi-stanza document must block inspection")
	}
	if !strings.Contains(got.BlockReason, "contains 2 non-comment stanzas") {
		t.Fatalf("unexpected block reason: %s", got.BlockReason)
	}
	if got.RenderedSource != "" || len(got.SnapshotTargets) != 0 {
		t.Fatalf("blocked inspection must not expose a prepared payload: %#v", got)
	}

	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}

func TestInspectApprovedDeb822RepairBlocksUnsupportedTarget(t *testing.T) {
	action := dockerDeb822RepairAction()
	action.Target.Distribution = "ubuntu"
	action.Target.Codename = "noble"

	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(validDockerDeb822Document()),
		},
	}

	got := InspectApprovedDeb822Repair(
		exec,
		action,
		dockerDeb822Profile(t),
	)

	if got.Ready {
		t.Fatal("unsupported Docker target must block inspection")
	}
	if !strings.Contains(got.BlockReason, "unable to render source") {
		t.Fatalf("unexpected block reason: %s", got.BlockReason)
	}
	if got.RenderedSource != "" || len(got.SnapshotTargets) != 0 {
		t.Fatalf("blocked inspection must not expose a prepared payload: %#v", got)
	}

	assertDeb822ReadOnlyCommand(t, exec.commands, 1)
}
