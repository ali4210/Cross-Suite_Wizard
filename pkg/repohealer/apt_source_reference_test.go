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

func TestParseAPTListSourceReferenceRejectsMarkdownWrappedURL(t *testing.T) {
	line := "/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] [https://download.docker.com/linux/debian](https://download.docker.com/linux/debian) bookworm stable"

	if _, ok := ParseAPTListSourceReference(line); ok {
		t.Fatal("Markdown-wrapped URL must not parse as a valid APT source")
	}
}

func TestParseAPTDeb822SourceReference(t *testing.T) {
	stanza := `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg`

	got, ok := ParseAPTDeb822SourceReference(
		"/etc/apt/sources.list.d/docker.sources",
		1,
		stanza,
	)

	if !ok {
		t.Fatal("expected Deb822 APT source reference to parse")
	}
	if got.SourceFile != "/etc/apt/sources.list.d/docker.sources" {
		t.Fatalf("source file = %q", got.SourceFile)
	}
	if got.LineNumber != 1 {
		t.Fatalf("stanza start line = %d", got.LineNumber)
	}
	if got.KeyringPath != "/etc/apt/keyrings/docker.gpg" {
		t.Fatalf("keyring path = %q", got.KeyringPath)
	}
	if got.RepositoryURL != "https://download.docker.com/linux/debian" {
		t.Fatalf("repository URL = %q", got.RepositoryURL)
	}
	if got.SourceLine != stanza {
		t.Fatalf("source stanza = %q", got.SourceLine)
	}
}

func TestParseAPTDeb822SourceReferenceRejectsMissingSignedBy(t *testing.T) {
	stanza := `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable`

	if _, ok := ParseAPTDeb822SourceReference(
		"/etc/apt/sources.list.d/docker.sources",
		1,
		stanza,
	); ok {
		t.Fatal("Deb822 stanza without Signed-By must not parse as a scoped keyring reference")
	}
}

func TestParseAPTDeb822SourceReferenceRejectsMarkdownWrappedURL(t *testing.T) {
	stanza := `Types: deb
URIs: [https://download.docker.com/linux/debian](https://download.docker.com/linux/debian)
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`

	if _, ok := ParseAPTDeb822SourceReference(
		"/etc/apt/sources.list.d/docker.sources",
		1,
		stanza,
	); ok {
		t.Fatal("Markdown-wrapped Deb822 URI must not parse as a valid APT source")
	}
}
