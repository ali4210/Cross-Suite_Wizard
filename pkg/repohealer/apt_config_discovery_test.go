package repohealer

import "testing"

func TestDiscoverAPTConfigFilesFindsListAndDeb822SourcesAndKeyrings(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n" +
				"/etc/apt/sources.list.d/hashicorp.list:1:deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com noble main\n" +
				"=== DEB822_SOURCES ===\n" +
				"--- DEB822_FILE_BEGIN ---\n" +
				"/etc/apt/sources.list.d/docker.sources\n" +
				"Types: deb\n" +
				"URIs: https://download.docker.com/linux/debian\n" +
				"Suites: bookworm\n" +
				"Components: stable\n" +
				"Architectures: amd64\n" +
				"Signed-By: /etc/apt/keyrings/docker.gpg\n" +
				"--- DEB822_FILE_END ---\n",
		},
	}

	got, err := DiscoverAPTConfigFiles(exec)
	if err != nil {
		t.Fatalf("DiscoverAPTConfigFiles() error = %v", err)
	}

	want := map[string]bool{
		"/etc/apt/sources.list.d/hashicorp.list":            true,
		"/usr/share/keyrings/hashicorp-archive-keyring.gpg": true,
		"/etc/apt/sources.list.d/docker.sources":            true,
		"/etc/apt/keyrings/docker.gpg":                      true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d: %v", len(got), len(want), got)
	}
	for _, path := range got {
		if !want[path] {
			t.Fatalf("unexpected discovered path %q", path)
		}
	}
}

func TestDiscoverAPTConfigFilesDeduplicates(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n" +
				"/etc/apt/sources.list.d/docker.list:1:deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable\n" +
				"/etc/apt/sources.list.d/docker.list:1:deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable\n" +
				"=== DEB822_SOURCES ===\n",
		},
	}

	got, err := DiscoverAPTConfigFiles(exec)
	if err != nil {
		t.Fatalf("DiscoverAPTConfigFiles() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected de-duplicated 2 paths, got %d: %v", len(got), got)
	}
}

func TestDiscoverAPTConfigFilesEmptyWhenNoSources(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{"=== APT_SOURCES ===\n=== DEB822_SOURCES ===\n"},
	}

	got, err := DiscoverAPTConfigFiles(exec)
	if err != nil {
		t.Fatalf("DiscoverAPTConfigFiles() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no discovered files, got %v", got)
	}
}
