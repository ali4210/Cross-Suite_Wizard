package playbook

import "testing"

// fakeRepoHealerExecutor is a minimal repohealer.Executor mock for testing the pure
// listing/parsing helpers in universal_healer.go without a real SSH client.
type fakeRepoHealerExecutor struct {
	runSudoOutputs []string
	runSudoErr     error
}

func (f *fakeRepoHealerExecutor) Run(command string) (string, error) {
	return "", nil
}

func (f *fakeRepoHealerExecutor) RunSudo(script string) (string, error) {
	if len(f.runSudoOutputs) == 0 {
		return "", f.runSudoErr
	}
	out := f.runSudoOutputs[0]
	f.runSudoOutputs = f.runSudoOutputs[1:]
	return out, f.runSudoErr
}

func (f *fakeRepoHealerExecutor) RunSudoWithLabel(script, label string) (string, error) {
	return f.RunSudo(script)
}

func TestListRepoHealerSnapshotsParsesAndSortsNewestFirst(t *testing.T) {
	exec := &fakeRepoHealerExecutor{
		runSudoOutputs: []string{
			"SNAPSHOT|apt-20240101T000000Z-aa|2024-01-01T00:00:00Z|targeted-apt-files\n" +
				"SNAPSHOT|apt-20240601T000000Z-bb|2024-06-01T00:00:00Z|targeted-apt-files\n",
		},
	}

	snapshots, err := listRepoHealerSnapshots(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}
	if snapshots[0].ID != "apt-20240601T000000Z-bb" {
		t.Fatalf("expected newest snapshot first, got %q", snapshots[0].ID)
	}
}

func TestListRepoHealerSnapshotsRejectsMalformedID(t *testing.T) {
	exec := &fakeRepoHealerExecutor{
		runSudoOutputs: []string{
			"SNAPSHOT|../../etc/passwd|2024-01-01T00:00:00Z|targeted-apt-files\n",
		},
	}

	snapshots, err := listRepoHealerSnapshots(exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("expected malformed snapshot id to be dropped, got %+v", snapshots)
	}
}

func TestListRepoHealerSnapshotFilesRejectsInvalidID(t *testing.T) {
	exec := &fakeRepoHealerExecutor{}

	_, err := listRepoHealerSnapshotFiles(exec, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected an error for a malformed snapshot id")
	}
}

func TestListRepoHealerSnapshotFilesParsesPaths(t *testing.T) {
	exec := &fakeRepoHealerExecutor{
		runSudoOutputs: []string{
			"FILE|/etc/apt/sources.list.d/docker.list\n" +
				"FILE|/etc/apt/keyrings/docker.gpg\n",
		},
	}

	files, err := listRepoHealerSnapshotFiles(exec, "apt-20240601T000000Z-bb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 ||
		files[0] != "/etc/apt/sources.list.d/docker.list" ||
		files[1] != "/etc/apt/keyrings/docker.gpg" {
		t.Fatalf("unexpected files: %+v", files)
	}
}
