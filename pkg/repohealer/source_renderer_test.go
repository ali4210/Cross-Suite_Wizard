package repohealer

import (
	"strings"
	"testing"
)

func TestRenderMicrosoftVSCodeAPTSource(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)
	if !ok {
		t.Fatal("expected Microsoft VS Code profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Distribution: "parrot",
		Codename:     "lory",
	})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderDockerAPTSourceForParrot64LoryUsesBookworm(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Distribution: "debian",
		Version:      "6.4",
		Codename:     "lory",
	})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	want := "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable"
	if got != want {
		t.Fatalf("RenderAPTSource() = %q, want %q", got, want)
	}
}

func TestRenderDockerAPTSourceForSupportedDebian(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	got, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "arm64",
		Distribution: "debian",
		Codename:     "trixie",
	})
	if err != nil {
		t.Fatalf("RenderAPTSource() error = %v", err)
	}

	if !strings.Contains(got, "arch=arm64") {
		t.Fatalf("expected arm64 source, got %q", got)
	}
	if !strings.Contains(got, " trixie stable") {
		t.Fatalf("expected trixie suite, got %q", got)
	}
}

func TestRenderDockerAPTSourceRejectsUnknownParrotCodename(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	_, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Distribution: "parrot",
		Codename:     "unknown-release",
	})
	if err == nil {
		t.Fatal("expected unsupported Parrot codename to be rejected")
	}
}

func TestRenderDockerAPTSourceRejectsUnsupportedDistribution(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	_, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Distribution: "ubuntu",
		Codename:     "noble",
	})
	if err == nil {
		t.Fatal("expected Ubuntu to be rejected for Docker Debian profile")
	}
}

func TestRenderDockerAPTSourceRejectsUnknownParrotLoryVersion(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	_, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: "amd64",
		Distribution: "debian",
		Version:      "6.5",
		Codename:     "lory",
	})
	if err == nil {
		t.Fatal("expected unknown Parrot lory version to be rejected")
	}
}
