package repohealer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendRawLine(path, line string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(line + "\n")
	return err
}

func TestAppendAndListSnapshotHistoryNewestFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	older := SnapshotHistoryEntry{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Target:    "host-a:22",
		Option:    "Option 7 mode [2]",
		Action:    "apt-keyring-repair-hashicorp",
		Result:    SnapshotHistoryResultApplied,
	}
	newer := SnapshotHistoryEntry{
		Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Target:    "host-a:22",
		Option:    "Option 9",
		Action:    "manual-checkpoint",
		Result:    SnapshotHistoryResultManualCheckpoint,
	}

	if err := AppendSnapshotHistoryEntry(path, older); err != nil {
		t.Fatalf("append older: %v", err)
	}
	if err := AppendSnapshotHistoryEntry(path, newer); err != nil {
		t.Fatalf("append newer: %v", err)
	}

	got, err := ListSnapshotHistory(path)
	if err != nil {
		t.Fatalf("ListSnapshotHistory() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].Action != "manual-checkpoint" || got[1].Action != "apt-keyring-repair-hashicorp" {
		t.Fatalf("expected newest-first order, got %+v", got)
	}
}

func TestListSnapshotHistoryMissingFileReturnsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.jsonl")

	got, err := ListSnapshotHistory(path)
	if err != nil {
		t.Fatalf("unexpected error for a missing history file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no entries, got %d", len(got))
	}
}

func TestListSnapshotHistorySkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	valid := SnapshotHistoryEntry{
		Timestamp: time.Now().UTC(),
		Action:    "valid-entry",
		Result:    SnapshotHistoryResultApplied,
	}
	if err := AppendSnapshotHistoryEntry(path, valid); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := appendRawLine(path, "{not valid json"); err != nil {
		t.Fatalf("append raw: %v", err)
	}

	got, err := ListSnapshotHistory(path)
	if err != nil {
		t.Fatalf("ListSnapshotHistory() error = %v", err)
	}
	if len(got) != 1 || got[0].Action != "valid-entry" {
		t.Fatalf("expected the one valid entry to survive, got %+v", got)
	}
}

func TestListSnapshotHistoryForTargetFiltersByHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	entries := []SnapshotHistoryEntry{
		{Timestamp: time.Now().UTC(), Target: "host-a:22", Action: "a1", Result: SnapshotHistoryResultApplied},
		{Timestamp: time.Now().UTC(), Target: "host-b:22", Action: "b1", Result: SnapshotHistoryResultApplied},
	}
	for _, entry := range entries {
		if err := AppendSnapshotHistoryEntry(path, entry); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	got, err := ListSnapshotHistoryForTarget(path, "host-a:22")
	if err != nil {
		t.Fatalf("ListSnapshotHistoryForTarget() error = %v", err)
	}
	if len(got) != 1 || got[0].Action != "a1" {
		t.Fatalf("expected only host-a entries, got %+v", got)
	}

	all, err := ListSnapshotHistoryForTarget(path, "")
	if err != nil {
		t.Fatalf("ListSnapshotHistoryForTarget(empty) error = %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected an empty target to match everything, got %d", len(all))
	}
}

func TestDiffPackageLists(t *testing.T) {
	before := "foo\t1.0\nbar\t2.0\n"
	after := "foo\t1.1\nbaz\t3.0\n"

	got := DiffPackageLists(before, after)

	for _, want := range []string{"+ foo\t1.1", "+ baz\t3.0", "- foo\t1.0", "- bar\t2.0"} {
		if !containsLine(got, want) {
			t.Fatalf("diff missing %q, got:\n%s", want, got)
		}
	}
}

func TestDiffPackageListsNoChanges(t *testing.T) {
	same := "foo\t1.0\n"
	got := DiffPackageLists(same, same)
	if got != "No package list differences." {
		t.Fatalf("got = %q, want no-differences message", got)
	}
}

func TestCapturePackageListScriptCoversEveryLinuxManagerExceptEmergeAndUnknown(t *testing.T) {
	tests := []struct {
		manager PackageManager
		want    bool
	}{
		{ManagerAPT, true},
		{ManagerDNF, true},
		{ManagerYUM, true},
		{ManagerZypper, true},
		{ManagerPacman, true},
		{ManagerAPK, true},
		{ManagerXBPS, true},
		{ManagerHomebrew, false}, // captured as a full Brewfile instead, see CreateHomebrewSnapshot
		{ManagerUnknown, false},
	}

	for _, test := range tests {
		t.Run(string(test.manager), func(t *testing.T) {
			_, ok := CapturePackageListScript(test.manager)
			if ok != test.want {
				t.Fatalf("CapturePackageListScript(%q) ok = %t, want %t", test.manager, ok, test.want)
			}
		})
	}
}

func TestCapturePackageListRunsReadOnlyCommand(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{"--- dpkg --get-selections ---\nfoo\tinstall\n"}}

	out, ok := CapturePackageList(exec, ManagerAPT)
	if !ok {
		t.Fatal("expected ManagerAPT to be supported")
	}
	if out == "" {
		t.Fatal("expected non-empty captured package list")
	}
	if len(exec.commands) != 1 || exec.commands[0][:4] != "RUN:" {
		t.Fatalf("expected a single non-sudo Run call, got %v", exec.commands)
	}
}

func TestSnapshotRetentionCountDefaultsAndRejectsInvalidOverride(t *testing.T) {
	t.Setenv("CROSS_SUITE_SNAPSHOT_RETENTION", "")
	if got := SnapshotRetentionCount(); got != 20 {
		t.Fatalf("default retention = %d, want 20", got)
	}

	t.Setenv("CROSS_SUITE_SNAPSHOT_RETENTION", "5")
	if got := SnapshotRetentionCount(); got != 5 {
		t.Fatalf("overridden retention = %d, want 5", got)
	}

	t.Setenv("CROSS_SUITE_SNAPSHOT_RETENTION", "-3")
	if got := SnapshotRetentionCount(); got != 20 {
		t.Fatalf("invalid negative override should fall back to default, got %d", got)
	}

	t.Setenv("CROSS_SUITE_SNAPSHOT_RETENTION", "not-a-number")
	if got := SnapshotRetentionCount(); got != 20 {
		t.Fatalf("unparsable override should fall back to default, got %d", got)
	}
}

func TestSnapshotIDsToPruneKeepsAtLeastOne(t *testing.T) {
	ids := []string{"apt-5", "apt-4", "apt-3", "apt-2", "apt-1"}

	got := SnapshotIDsToPrune(ids, 2)
	want := []string{"apt-3", "apt-2", "apt-1"}
	if len(got) != len(want) {
		t.Fatalf("got = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if got := SnapshotIDsToPrune(ids, 0); len(got) != len(ids)-1 {
		t.Fatalf("retain=0 must still keep at least one snapshot, pruned %d of %d", len(got), len(ids))
	}

	if got := SnapshotIDsToPrune([]string{"only-one"}, 20); got != nil {
		t.Fatalf("a single snapshot must never be pruned, got %v", got)
	}
}

func containsLine(haystack, needle string) bool {
	for _, line := range splitLines(haystack) {
		if line == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}
