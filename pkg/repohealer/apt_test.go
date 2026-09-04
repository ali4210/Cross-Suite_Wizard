package repohealer

import (
	"strings"
	"testing"
)

func TestExtractRepositoryURL(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "Microsoft VS Code source",
			line: "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main",
			want: "https://packages.microsoft.com/repos/code",
		},
		{
			name: "Docker source",
			line: "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable",
			want: "https://download.docker.com/linux/debian",
		},
		{
			name: "No URL",
			line: "deb [signed-by=/etc/apt/keyrings/example.gpg] stable main",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRepositoryURL(tt.line)
			if got != tt.want {
				t.Fatalf("extractRepositoryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRepositoryNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{
			url:  "https://packages.microsoft.com/repos/code",
			want: "Microsoft Visual Studio Code",
		},
		{
			url:  "https://download.docker.com/linux/debian",
			want: "Docker",
		},
		{
			url:  "https://apt.releases.hashicorp.com",
			want: "HashiCorp",
		},
		{
			url:  "https://packages.wazuh.com/4.x/apt",
			want: "Wazuh",
		},
		{
			url:  "https://example.invalid/repository",
			want: "Unidentified APT Repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := repositoryNameFromURL(tt.url)
			if got != tt.want {
				t.Fatalf("repositoryNameFromURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMicrosoftVSCodeProfile(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)

	if !ok {
		t.Fatal("expected Microsoft VS Code vendor profile to be found")
	}

	if profile.ID != "microsoft-vscode" {
		t.Fatalf("profile ID = %q, want %q", profile.ID, "microsoft-vscode")
	}

	if profile.KeyringPath != "/etc/apt/keyrings/microsoft.gpg" {
		t.Fatalf("keyring path = %q", profile.KeyringPath)
	}

	if len(profile.ExpectedFingerprints) != 1 {
		t.Fatalf("expected exactly one pinned fingerprint, got %d", len(profile.ExpectedFingerprints))
	}

	wantFingerprint := "BC528686B50D79E339D3721CEB3E94ADBE1229CF"
	if !IsPinnedFingerprint(profile, wantFingerprint) {
		t.Fatalf("expected fingerprint %s to be pinned", wantFingerprint)
	}

	if IsPinnedFingerprint(profile, "0000000000000000000000000000000000000000") {
		t.Fatal("unexpected unknown fingerprint accepted")
	}
}

func TestUnknownRepositoryHasNoProfile(t *testing.T) {
	_, ok := FindVendorProfile(
		ManagerAPT,
		"https://unknown.example.invalid/apt",
	)

	if ok {
		t.Fatal("unknown repository must not receive a known-vendor profile")
	}
}

func TestSourceLineUsesScopedKeyring(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)
	if !ok {
		t.Fatal("expected Microsoft VS Code profile")
	}

	if !strings.Contains(profile.SourceLine, "signed-by=/etc/apt/keyrings/microsoft.gpg") {
		t.Fatalf("source line must use the scoped Microsoft keyring: %q", profile.SourceLine)
	}

	if strings.Contains(profile.SourceLine, "trusted=yes") {
		t.Fatalf("source line must not bypass APT trust verification: %q", profile.SourceLine)
	}
}
