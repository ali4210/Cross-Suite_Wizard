package repohealer

import "testing"

func TestParseAPTListSourceReference(t *testing.T) {
	line := "/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/old-docker.gpg] https://download.docker.com/linux/debian bookworm stable"

	got, ok := ParseAPTListSourceReference(line)

	if !ok {
		t.Fatal("expected classic APT source reference to parse")
	}
	if got.SourceFile != "/etc/apt/sources.list.d/docker.list" {
		t.Fatalf("source file = %q", got.SourceFile)
	}
	if got.LineNumber != 1 {
		t.Fatalf("line number = %d", got.LineNumber)
	}
	if got.KeyringPath != "/etc/apt/keyrings/old-docker.gpg" {
		t.Fatalf("keyring path = %q", got.KeyringPath)
	}
	if got.RepositoryURL != "https://download.docker.com/linux/debian" {
		t.Fatalf("repository URL = %q", got.RepositoryURL)
	}
	if got.SourceLine != "deb [arch=amd64 signed-by=/etc/apt/keyrings/old-docker.gpg] https://download.docker.com/linux/debian bookworm stable" {
		t.Fatalf("source line = %q", got.SourceLine)
	}
}

func TestParseAPTListSourceReferenceRejectsLineWithoutSignedBy(t *testing.T) {
	line := "/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64] https://download.docker.com/linux/debian bookworm stable"

	if _, ok := ParseAPTListSourceReference(line); ok {
		t.Fatal("source line without signed-by must not parse as a scoped keyring reference")
	}
}
