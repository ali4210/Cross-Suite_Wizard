package repohealer

import "strings"

type VendorProfile struct {
	ID                   string
	DisplayName          string
	PackageManager       PackageManager
	AllowedURLPrefixes   []string
	KeyURL               string
	KeyringPath          string
	ExpectedFingerprints []string
	SourceFile           string
	SourceLine           string

	// DocSource cites where ExpectedFingerprints was verified against (the vendor's own
	// documentation page, or "key URL only" when the vendor's docs do not publish a
	// fingerprint and the key was instead verified by downloading it from the vendor's own
	// documented HTTPS KeyURL in a container). Every entry in KnownVendorProfiles must set
	// this — see the per-entry comments for the exact verification date and method.
	DocSource string

	// Suite and Components are the APT distribution/component for a vendor whose repository
	// uses one fixed suite regardless of the target distribution (e.g. "stable"/"main").
	// RenderAPTSource and RenderAPTDeb822Source fall back to these generically when a
	// vendor has no distribution-specific switch case of its own. Leave both empty for a
	// vendor that needs codename-conditional resolution (see CodenameSuiteSuffix) or a
	// custom renderer case.
	Suite      string
	Components string

	// CodenameSuiteSuffix and SupportedCodenames describe a vendor whose suite is the
	// target's own distro codename plus a fixed suffix (e.g. PostgreSQL PGDG's
	// "<codename>-pgdg"), restricted to the codenames the vendor documents support for.
	// Leave both empty for a vendor using a single fixed Suite instead.
	CodenameSuiteSuffix string
	SupportedCodenames  []string
}

func KnownVendorProfiles() []VendorProfile {
	return []VendorProfile{
		{
			ID:             "microsoft-vscode",
			DisplayName:    "Microsoft Visual Studio Code",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://packages.microsoft.com/repos/code",
			},
			KeyURL:      "https://packages.microsoft.com/keys/microsoft.asc",
			KeyringPath: "/etc/apt/keyrings/microsoft.gpg",
			ExpectedFingerprints: []string{
				"BC528686B50D79E339D3721CEB3E94ADBE1229CF",
			},
			SourceFile: "/etc/apt/sources.list.d/vscode.list",
			SourceLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main",
			DocSource:  "https://code.visualstudio.com/docs/setup/linux (verified by downloading KeyURL)",
		},
		{
			ID:             "hashicorp",
			DisplayName:    "HashiCorp",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://apt.releases.hashicorp.com",
			},
			KeyURL:      "https://apt.releases.hashicorp.com/gpg",
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			ExpectedFingerprints: []string{
				"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
			},
			SourceFile: "/etc/apt/sources.list.d/hashicorp.list",
			DocSource:  "https://apt.releases.hashicorp.com/gpg (re-verified live in an ubuntu:24.04 container, 2026-11-12)",
		},
		{
			ID:             "docker-ce",
			DisplayName:    "Docker CE",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://download.docker.com/linux/debian",
			},
			KeyURL:      "https://download.docker.com/linux/debian/gpg",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			ExpectedFingerprints: []string{
				"9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
				"D3306A018370199E527AE7997EA0A9C3F273FCD8",
			},
			SourceFile: "/etc/apt/sources.list.d/docker.list",
			DocSource:  "https://docs.docker.com/engine/install/debian/ (verified by downloading KeyURL)",
		},
		{
			// Verified 2026-11-12: downloaded https://dl.google.com/linux/linux_signing_key.pub
			// in an ubuntu:24.04 container (gpg --show-keys --with-colons --fingerprint). That
			// file bundles 9 keys shared across several Google Linux products; the one pinned
			// here is specifically the one https://www.google.com/linuxrepositories/ names as
			// the "active primary key" (its "obsolete key" 4CCA1EAF950CEE4AB83976DCA040830F7FAC5991
			// is deliberately NOT pinned). The other 8 bundled keys are not relevant to this repo.
			ID:             "google-chrome",
			DisplayName:    "Google Chrome",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://dl.google.com/linux/chrome/deb",
				"http://dl.google.com/linux/chrome/deb",
			},
			KeyURL:      "https://dl.google.com/linux/linux_signing_key.pub",
			KeyringPath: "/etc/apt/keyrings/google-chrome.gpg",
			ExpectedFingerprints: []string{
				"EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
			},
			SourceFile: "/etc/apt/sources.list.d/google-chrome.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://www.google.com/linuxrepositories/ (fingerprint published as the \"active primary key\"), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: official docs (github.com/cli/cli docs/install_linux.md)
			// explicitly publish both fingerprints below; confirmed by downloading KeyURL in
			// an ubuntu:24.04 container. The downloaded keyring also contains two other
			// fingerprints NOT published by the docs, which are deliberately not pinned here.
			ID:             "github-cli",
			DisplayName:    "GitHub CLI",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://cli.github.com/packages",
			},
			KeyURL:      "https://cli.github.com/packages/githubcli-archive-keyring.gpg",
			KeyringPath: "/etc/apt/keyrings/githubcli-archive-keyring.gpg",
			ExpectedFingerprints: []string{
				"2C6106201985B60E6C7AC87323F3D4EA75716059",
				"7F38BBB59D064DBCB3D84D725612B36462313325",
			},
			SourceFile: "/etc/apt/sources.list.d/github-cli.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://github.com/cli/cli/blob/trunk/docs/install_linux.md (publishes both fingerprints), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: official docs (postgresql.org/download/linux/ubuntu)
			// publish this exact fingerprint via `gpg --show-key`'s documented output;
			// confirmed by downloading KeyURL in an ubuntu:24.04 container. The repository
			// suite is the target's own codename plus "-pgdg", restricted to the codenames
			// that page documents as supported (Debian codenames are not included here, since
			// only the Ubuntu install page was checked in this pass).
			ID:             "postgresql-pgdg",
			DisplayName:    "PostgreSQL (PGDG)",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://apt.postgresql.org/pub/repos/apt",
			},
			KeyURL:      "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
			KeyringPath: "/etc/apt/keyrings/postgresql-pgdg.asc",
			ExpectedFingerprints: []string{
				"B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
			},
			SourceFile:          "/etc/apt/sources.list.d/pgdg.list",
			Components:          "main",
			CodenameSuiteSuffix: "-pgdg",
			SupportedCodenames:  []string{"noble", "jammy", "resolute", "stonking"},
			DocSource:           "https://www.postgresql.org/download/linux/ubuntu/ (publishes the fingerprint via documented gpg --show-key output), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: downloaded the CURRENT key URL
			// (jenkins.io-2026.key) in an ubuntu:24.04 container. Jenkins' official docs
			// (jenkins.io/doc/book/installing/linux) rotate this key URL's year segment
			// roughly annually (an older "-2023.key" fingerprint from a prior check no longer
			// matches) — this profile pins the fingerprint for the URL documented as current
			// as of the verification date above; it will need updating when Jenkins rotates
			// the key again.
			ID:             "jenkins",
			DisplayName:    "Jenkins",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://pkg.jenkins.io/debian-stable",
			},
			KeyURL:      "https://pkg.jenkins.io/debian-stable/jenkins.io-2026.key",
			KeyringPath: "/etc/apt/keyrings/jenkins-keyring.asc",
			ExpectedFingerprints: []string{
				"5E386EADB55F01504CAE8BCF7198F4B714ABFC68",
			},
			SourceFile: "/etc/apt/sources.list.d/jenkins.list",
			Suite:      "binary/",
			Components: "",
			DocSource:  "https://www.jenkins.io/doc/book/installing/linux/ (documents the current key URL), verified by downloading KeyURL, 2026-11-12",
		},
	}
}

func FindVendorProfile(manager PackageManager, repositoryURL string) (VendorProfile, bool) {
	repositoryURL = strings.TrimSpace(repositoryURL)

	for _, profile := range KnownVendorProfiles() {
		if profile.PackageManager != manager {
			continue
		}

		for _, prefix := range profile.AllowedURLPrefixes {
			if repositoryURL == prefix ||
				strings.HasPrefix(repositoryURL, prefix+"/") {
				return profile, true
			}
		}
	}

	return VendorProfile{}, false
}

func IsPinnedFingerprint(profile VendorProfile, fingerprint string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""))

	for _, expected := range profile.ExpectedFingerprints {
		if normalized == strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(expected), " ", "")) {
			return true
		}
	}

	return false
}
