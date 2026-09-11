package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestReadApprovedDeb822SourceReturnsDecodedDocument(t *testing.T) {
	document := validDockerDeb822Document()
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			deb822ReaderOutput(document),
		},
	}

	got, err := ReadApprovedDeb822Source(
		exec,
		dockerDeb822RepairAction(),
	)
	if err != nil {
		t.Fatalf("ReadApprovedDeb822Source() error = %v", err)
	}
	if got != document {
		t.Fatalf("document = %q, want %q", got, document)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(exec.commands))
	}

	command := exec.commands[0]
	for _, expected := range []string{
		"Reading Approved Deb822 APT Source",
		`SOURCE_FILE="/etc/apt/sources.list.d/docker.sources"`,
		"stat -c",
		"base64 --",
		"-L",
		"-f",
		"MAX_BYTES=65536",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("reader command missing %q:\n%s", expected, command)
		}
	}

	for _, unexpected := range []string{
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
	} {
		if strings.Contains(command, unexpected) {
			t.Fatalf(
				"reader command must not contain mutation or repair token %q:\n%s",
				unexpected,
				command,
			)
		}
	}
}

func TestReadApprovedDeb822SourceRejectsUnsafeActionsWithoutCommands(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*RepairAction)
		wantReason string
	}{
		{
			name: "Empty path",
			mutate: func(action *RepairAction) {
				action.SourceFile = ""
			},
			wantReason: "source file is empty",
		},
		{
			name: "List path",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/etc/apt/sources.list.d/docker.list"
			},
			wantReason: "does not have a .sources suffix",
		},
		{
			name: "Nested path",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/etc/apt/sources.list.d/nested/docker.sources"
			},
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			name: "Outside path",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/tmp/docker.sources"
			},
			wantReason: "is outside /etc/apt/sources.list.d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := dockerDeb822RepairAction()
			test.mutate(&action)

			exec := &fakeExecutor{}
			_, err := ReadApprovedDeb822Source(exec, action)

			if err == nil {
				t.Fatal("unsafe action unexpectedly started a reader command")
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
			if len(exec.commands) != 0 {
				t.Fatalf(
					"unsafe action must not issue reader commands: %v",
					exec.commands,
				)
			}
		})
	}
}

func TestReadApprovedDeb822SourceRejectsReaderFailures(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		err        error
		wantReason string
	}{
		{
			name:       "Missing file",
			output:     deb822ReaderError("missing"),
			err:        errors.New("exit status 10"),
			wantReason: "read blocked: missing",
		},
		{
			name:       "Symlink",
			output:     deb822ReaderError("symlink"),
			err:        errors.New("exit status 11"),
			wantReason: "read blocked: symlink",
		},
		{
			name:       "Unexpected owner",
			output:     deb822ReaderError("unexpected_owner|uid=1000|gid=1000"),
			err:        errors.New("exit status 13"),
			wantReason: "read blocked: unexpected_owner",
		},
		{
			name:       "Writable by group",
			output:     deb822ReaderError("writable_by_group_or_other|mode=664"),
			err:        errors.New("exit status 15"),
			wantReason: "read blocked: writable_by_group_or_other",
		},
		{
			name:       "File too large",
			output:     deb822ReaderError("file_too_large|size=65537|max=65536"),
			err:        errors.New("exit status 17"),
			wantReason: "read blocked: file_too_large",
		},
		{
			name:       "Unreadable",
			output:     deb822ReaderError("unreadable"),
			err:        errors.New("exit status 18"),
			wantReason: "read blocked: unreadable",
		},
		{
			name:       "Invalid envelope",
			output:     "unexpected output",
			wantReason: "invalid reader output envelope",
		},
		{
			name:       "Invalid base64",
			output:     deb822SourceReadBegin + "\n%%%\n" + deb822SourceReadEnd,
			wantReason: "invalid base64 content",
		},
		{
			name:       "Empty encoded content",
			output:     deb822SourceReadBegin + "\n\n" + deb822SourceReadEnd,
			wantReason: "source content was empty",
		},
		{
			name:       "Empty decoded content",
			output:     deb822ReaderOutput(""),
			wantReason: "source content was empty",
		},
		{
			name:       "Command failure after valid output",
			output:     deb822ReaderOutput(validDockerDeb822Document()),
			err:        errors.New("ssh transport failed"),
			wantReason: "Deb822 source read failed: ssh transport failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exec := &fakeExecutor{
				runSudoLabelOutputs: []string{test.output},
				runSudoLabelErrors:  []error{test.err},
			}

			_, err := ReadApprovedDeb822Source(
				exec,
				dockerDeb822RepairAction(),
			)

			if err == nil {
				t.Fatal("reader failure unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
			if len(exec.commands) != 1 {
				t.Fatalf(
					"reader failure must issue exactly one reader command, got %d",
					len(exec.commands),
				)
			}
		})
	}
}

func TestParseApprovedDeb822SourceReadOutputRejectsOversizedDecodedContent(t *testing.T) {
	document := strings.Repeat("a", maxDeb822SourceBytes+1)

	_, err := parseApprovedDeb822SourceReadOutput(
		deb822ReaderOutput(document),
	)
	if err == nil {
		t.Fatal("oversized decoded document unexpectedly parsed")
	}
	if !strings.Contains(err.Error(), "decoded content exceeds") {
		t.Fatalf("unexpected oversized-content error: %v", err)
	}
}
