package repohealer

import (
	"strings"
	"testing"
)

func dockerDeb822Profile(t *testing.T) VendorProfile {
	t.Helper()

	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	return profile
}

func microsoftDeb822Profile(t *testing.T) VendorProfile {
	t.Helper()

	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://packages.microsoft.com/repos/code",
	)
	if !ok {
		t.Fatal("expected Microsoft VS Code profile")
	}

	return profile
}

func TestValidateSingleProfileDeb822DocumentAcceptsSafeDocuments(t *testing.T) {
	tests := []struct {
		name             string
		profile          VendorProfile
		document         string
		wantRepository   string
		wantKeyring      string
		wantArchitecture string
	}{
		{
			name:    "Docker without Architectures",
			profile: dockerDeb822Profile(t),
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantRepository: "https://download.docker.com/linux/debian",
			wantKeyring:    "/etc/apt/keyrings/docker.gpg",
		},
		{
			name:    "Docker with one architecture",
			profile: dockerDeb822Profile(t),
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantRepository:   "https://download.docker.com/linux/debian",
			wantKeyring:      "/etc/apt/keyrings/docker.gpg",
			wantArchitecture: "amd64",
		},
		{
			name:    "Microsoft VS Code",
			profile: microsoftDeb822Profile(t),
			document: `Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/microsoft.gpg`,
			wantRepository:   "https://packages.microsoft.com/repos/code",
			wantKeyring:      "/etc/apt/keyrings/microsoft.gpg",
			wantArchitecture: "amd64",
		},
		{
			name:           "Comments and CRLF",
			profile:        dockerDeb822Profile(t),
			document:       "# Docker repository\r\n\r\nTypes: deb\r\nURIs: https://download.docker.com/linux/debian\r\nSuites: bookworm\r\nComponents: stable\r\nSigned-By: /etc/apt/keyrings/docker.gpg\r\n# End\r\n",
			wantRepository: "https://download.docker.com/linux/debian",
			wantKeyring:    "/etc/apt/keyrings/docker.gpg",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ValidateSingleProfileDeb822Document(
				test.document,
				test.profile,
			)

			if !got.Valid {
				t.Fatalf("validation unexpectedly failed: %s", got.Reason)
			}
			if got.StanzaCount != 1 {
				t.Fatalf("stanza count = %d, want 1", got.StanzaCount)
			}
			if got.RepositoryURL != test.wantRepository {
				t.Fatalf(
					"repository URL = %q, want %q",
					got.RepositoryURL,
					test.wantRepository,
				)
			}
			if got.KeyringPath != test.wantKeyring {
				t.Fatalf(
					"keyring path = %q, want %q",
					got.KeyringPath,
					test.wantKeyring,
				)
			}
			if got.Architecture != test.wantArchitecture {
				t.Fatalf(
					"architecture = %q, want %q",
					got.Architecture,
					test.wantArchitecture,
				)
			}
		})
	}
}

func TestValidateSingleProfileDeb822DocumentRejectsUnsafeDocuments(t *testing.T) {
	docker := dockerDeb822Profile(t)

	tests := []struct {
		name       string
		document   string
		wantReason string
	}{
		{
			name:       "Empty document",
			document:   "",
			wantReason: "contains no non-comment stanzas",
		},
		{
			name:       "Comments only",
			document:   "# Docker\n  # Still no source\n",
			wantReason: "contains no non-comment stanzas",
		},
		{
			name: "Two stanzas",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg

Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "contains 2 non-comment stanzas",
		},
		{
			name: "Missing Types",
			document: `URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "missing required field \"Types\"",
		},
		{
			name: "Missing URIs",
			document: `Types: deb
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "missing required field \"URIs\"",
		},
		{
			name: "Missing Suites",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "missing required field \"Suites\"",
		},
		{
			name: "Missing Components",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "missing required field \"Components\"",
		},
		{
			name: "Missing Signed-By",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable`,
			wantReason: "missing required field \"Signed-By\"",
		},
		{
			name: "Multiple types",
			document: `Types: deb deb-src
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "Types must be exactly",
		},
		{
			name: "Multiple URIs",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian https://example.invalid/apt
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "URIs must contain exactly one repository URL",
		},
		{
			name: "Markdown wrapped URI",
			document: `Types: deb
URIs: [https://download.docker.com/linux/debian](https://download.docker.com/linux/debian)
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "URIs must contain one plain HTTPS repository URL",
		},
		{
			name: "Prefix extension",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian/extra
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "not an exact allowlisted repository URL",
		},
		{
			name: "Wrong keyring",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/old-docker.gpg`,
			wantReason: "does not match profile keyring",
		},
		{
			name: "Duplicate Signed-By",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "repeats field \"Signed-By\"",
		},
		{
			name: "Duplicate arbitrary field",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg
Enabled: yes
Enabled: no`,
			wantReason: "repeats field \"enabled\"",
		},
		{
			name: "Multiple architectures",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "Architectures must contain exactly one architecture token",
		},
		{
			name: "Malformed field line",
			document: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg`,
			wantReason: "contains malformed field line",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ValidateSingleProfileDeb822Document(test.document, docker)

			if got.Valid {
				t.Fatalf("unsafe document unexpectedly validated: %#v", got)
			}
			if got.StanzaCount == 0 &&
				!strings.Contains(test.wantReason, "no non-comment stanzas") {
				t.Fatalf("unexpected zero stanza count: %#v", got)
			}
			if !strings.Contains(got.Reason, test.wantReason) {
				t.Fatalf(
					"reason = %q, want it to contain %q",
					got.Reason,
					test.wantReason,
				)
			}
		})
	}
}
