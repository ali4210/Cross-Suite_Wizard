package repohealer

import (
	"strings"
	"testing"
)

func dockerDeb822RepairAction() RepairAction {
	return RepairAction{
		ID:              APTRepairActionID("docker-ce", "APT_KEYRING_PATH_MISSING"),
		FindingCode:     "APT_KEYRING_PATH_MISSING",
		Eligible:        true,
		RequiresConsent: true,
		ProfileID:       "docker-ce",
		RepositoryURL:   "https://download.docker.com/linux/debian",
		KeyringPath:     "/etc/apt/keyrings/docker.gpg",
		SourceFile:      "/etc/apt/sources.list.d/docker.sources",
		SourceLine:      1,
		SourceFormat:    SourceFormatDeb822,
		SnapshotTargets: []string{
			"/etc/apt/sources.list.d/docker.sources",
			"/etc/apt/keyrings/docker.gpg",
		},
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
	}
}

func validDockerDeb822Document() string {
	return `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`
}

func TestPrepareDeb822RepairBuildsApprovedDockerPayload(t *testing.T) {
	profile := dockerDeb822Profile(t)
	action := dockerDeb822RepairAction()

	got, err := PrepareDeb822Repair(
		action,
		profile,
		validDockerDeb822Document(),
	)
	if err != nil {
		t.Fatalf("PrepareDeb822Repair() error = %v", err)
	}

	if got.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q, want docker-ce", got.ProfileID)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.KeyringPath != profile.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, profile.KeyringPath)
	}

	wantSource := `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`
	if got.RenderedSource != wantSource {
		t.Fatalf(
			"rendered Deb822 source = %q, want %q",
			got.RenderedSource,
			wantSource,
		)
	}

	wantTargets := []string{
		action.SourceFile,
		profile.KeyringPath,
	}
	if len(got.SnapshotTargets) != len(wantTargets) {
		t.Fatalf(
			"snapshot target count = %d, want %d",
			len(got.SnapshotTargets),
			len(wantTargets),
		)
	}
	for index, want := range wantTargets {
		if got.SnapshotTargets[index] != want {
			t.Fatalf(
				"snapshot target %d = %q, want %q",
				index,
				got.SnapshotTargets[index],
				want,
			)
		}
	}
}

func TestPrepareDeb822RepairRejectsUnsafeInputs(t *testing.T) {
	profile := dockerDeb822Profile(t)

	tests := []struct {
		name       string
		mutate     func(*RepairAction)
		document   string
		wantReason string
	}{
		{
			name: "Ineligible action",
			mutate: func(action *RepairAction) {
				action.Eligible = false
			},
			document:   validDockerDeb822Document(),
			wantReason: "is not eligible",
		},
		{
			name: "No consent requirement",
			mutate: func(action *RepairAction) {
				action.RequiresConsent = false
			},
			document:   validDockerDeb822Document(),
			wantReason: "does not require explicit consent",
		},
		{
			name: "APT list action",
			mutate: func(action *RepairAction) {
				action.SourceFormat = SourceFormatAPTList
			},
			document:   validDockerDeb822Document(),
			wantReason: "is not Deb822",
		},
		{
			name: "Unknown finding",
			mutate: func(action *RepairAction) {
				action.FindingCode = "UNKNOWN_FINDING"
			},
			document:   validDockerDeb822Document(),
			wantReason: "unsupported APT finding code",
		},
		{
			name: "Profile mismatch",
			mutate: func(action *RepairAction) {
				action.ProfileID = "microsoft-vscode"
			},
			document:   validDockerDeb822Document(),
			wantReason: "does not match verified profile",
		},
		{
			name: "Repository prefix extension",
			mutate: func(action *RepairAction) {
				action.RepositoryURL = "https://download.docker.com/linux/debian/extra"
			},
			document:   validDockerDeb822Document(),
			wantReason: "is not exact for profile",
		},
		{
			name: "Keyring mismatch",
			mutate: func(action *RepairAction) {
				action.KeyringPath = "/etc/apt/keyrings/old-docker.gpg"
			},
			document:   validDockerDeb822Document(),
			wantReason: "does not match verified profile keyring path",
		},
		{
			name: "Source outside approved directory",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/tmp/docker.sources"
			},
			document:   validDockerDeb822Document(),
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			name: "Nested source path",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/etc/apt/sources.list.d/nested/docker.sources"
			},
			document:   validDockerDeb822Document(),
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			name: "List suffix",
			mutate: func(action *RepairAction) {
				action.SourceFile = "/etc/apt/sources.list.d/docker.list"
			},
			document:   validDockerDeb822Document(),
			wantReason: "does not have a .sources suffix",
		},
		{
			name: "Empty source path",
			mutate: func(action *RepairAction) {
				action.SourceFile = ""
			},
			document:   validDockerDeb822Document(),
			wantReason: "source file is empty",
		},
		{
			name:   "Multiple document stanzas",
			mutate: func(action *RepairAction) {},
			document: validDockerDeb822Document() + `
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Signed-By: /etc/apt/keyrings/docker.gpg
`,
			wantReason: "contains 2 non-comment stanzas",
		},
		{
			name:   "Wrong document keyring",
			mutate: func(action *RepairAction) {},
			document: strings.Replace(
				validDockerDeb822Document(),
				"/etc/apt/keyrings/docker.gpg",
				"/etc/apt/keyrings/old-docker.gpg",
				1,
			),
			wantReason: "does not match profile keyring",
		},
		{
			name:       "Unsupported Docker target",
			mutate:     func(action *RepairAction) {},
			document:   validDockerDeb822Document(),
			wantReason: "unable to render source",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := dockerDeb822RepairAction()
			test.mutate(&action)

			if test.name == "Unsupported Docker target" {
				action.Target.Distribution = "ubuntu"
				action.Target.Codename = "noble"
			}

			got, err := PrepareDeb822Repair(action, profile, test.document)

			if err == nil {
				t.Fatalf(
					"PrepareDeb822Repair() unexpectedly succeeded: %#v",
					got,
				)
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
			if got.ProfileID != "" ||
				got.SourceFile != "" ||
				got.KeyringPath != "" ||
				got.RenderedSource != "" ||
				len(got.SnapshotTargets) != 0 {
				t.Fatalf(
					"blocked preparation must return an empty payload, got %#v",
					got,
				)
			}
		})
	}
}

func TestValidateApprovedDeb822SourcePath(t *testing.T) {
	tests := []struct {
		path       string
		wantReason string
	}{
		{
			path: "/etc/apt/sources.list.d/docker.sources",
		},
		{
			path:       "",
			wantReason: "source file is empty",
		},
		{
			path:       "/etc/apt/sources.list.d/docker.list",
			wantReason: "does not have a .sources suffix",
		},
		{
			path:       "/etc/apt/sources.list.d/.sources",
			wantReason: "has an empty basename",
		},
		{
			path:       "/etc/apt/sources.list.d/nested/docker.sources",
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			path:       "/etc/apt/sources.list.d/../docker.sources",
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			path:       "/tmp/docker.sources",
			wantReason: "is outside /etc/apt/sources.list.d",
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			err := validateApprovedDeb822SourcePath(test.path)

			if test.wantReason == "" {
				if err != nil {
					t.Fatalf("path validation unexpectedly failed: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("path validation unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
		})
	}
}
