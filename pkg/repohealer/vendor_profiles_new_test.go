package repohealer

import "testing"

// TestKnownVendorProfilesAllHaveDocSource guards the "never invent facts" rule at the data
// layer: every vendor profile must cite where its ExpectedFingerprints was verified.
func TestKnownVendorProfilesAllHaveDocSource(t *testing.T) {
	for _, profile := range KnownVendorProfiles() {
		if profile.DocSource == "" {
			t.Fatalf("vendor profile %q has no DocSource citation", profile.ID)
		}
		if len(profile.ExpectedFingerprints) == 0 {
			t.Fatalf("vendor profile %q has no pinned fingerprint", profile.ID)
		}
	}
}

func TestRenderGoogleChromeAPTSource(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://dl.google.com/linux/chrome/deb")
	if !ok {
		t.Fatal("expected Google Chrome profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{Architecture: "amd64"})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb stable main"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderGitHubCLIAPTSource(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://cli.github.com/packages")
	if !ok {
		t.Fatal("expected GitHub CLI profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{Architecture: "amd64"})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderJenkinsAPTSourceIsFlatRepoWithNoArchOrComponents(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://pkg.jenkins.io/debian-stable")
	if !ok {
		t.Fatal("expected Jenkins profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{Architecture: "amd64"})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [signed-by=/etc/apt/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderPostgreSQLPGDGAPTSourceResolvesCodenameSuite(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://apt.postgresql.org/pub/repos/apt")
	if !ok {
		t.Fatal("expected PostgreSQL PGDG profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Codename:     "noble",
	})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [arch=amd64 signed-by=/etc/apt/keyrings/postgresql-pgdg.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderPostgreSQLPGDGAPTSourceRejectsUnsupportedCodename(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://apt.postgresql.org/pub/repos/apt")
	if !ok {
		t.Fatal("expected PostgreSQL PGDG profile")
	}

	_, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Codename:     "unknown-codename",
	})
	if err == nil {
		t.Fatal("expected an error for an unsupported codename")
	}
}

func TestRenderPostgreSQLPGDGDeb822Source(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://apt.postgresql.org/pub/repos/apt")
	if !ok {
		t.Fatal("expected PostgreSQL PGDG profile")
	}

	got, err := RenderAPTDeb822Source(profile, SourceRenderInput{
		Architecture: "amd64",
		Codename:     "jammy",
	})
	if err != nil {
		t.Fatalf("RenderAPTDeb822Source() error = %v", err)
	}

	want := "Types: deb\n" +
		"URIs: https://apt.postgresql.org/pub/repos/apt\n" +
		"Suites: jammy-pgdg\n" +
		"Components: main\n" +
		"Architectures: amd64\n" +
		"Signed-By: /etc/apt/keyrings/postgresql-pgdg.asc\n"
	if got != want {
		t.Fatalf("RenderAPTDeb822Source() = %q, want %q", got, want)
	}
}

func TestRenderGoogleChromeDeb822Source(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://dl.google.com/linux/chrome/deb")
	if !ok {
		t.Fatal("expected Google Chrome profile")
	}

	got, err := RenderAPTDeb822Source(profile, SourceRenderInput{Architecture: "amd64"})
	if err != nil {
		t.Fatalf("RenderAPTDeb822Source() error = %v", err)
	}

	want := "Types: deb\n" +
		"URIs: https://dl.google.com/linux/chrome/deb\n" +
		"Suites: stable\n" +
		"Components: main\n" +
		"Architectures: amd64\n" +
		"Signed-By: /etc/apt/keyrings/google-chrome.gpg\n"
	if got != want {
		t.Fatalf("RenderAPTDeb822Source() = %q, want %q", got, want)
	}
}

func TestRenderJenkinsDeb822SourceIsNotImplemented(t *testing.T) {
	profile, ok := FindVendorProfile(ManagerAPT, "https://pkg.jenkins.io/debian-stable")
	if !ok {
		t.Fatal("expected Jenkins profile")
	}

	// Jenkins' own documentation only shows the classic flat-repo .list format, never a
	// Deb822 .sources example — so no Deb822 renderer is implemented for it, and this must
	// fail rather than invent an undocumented format.
	if _, err := RenderAPTDeb822Source(profile, SourceRenderInput{Architecture: "amd64"}); err == nil {
		t.Fatal("expected an error: Jenkins has no documented Deb822 format")
	}
}
