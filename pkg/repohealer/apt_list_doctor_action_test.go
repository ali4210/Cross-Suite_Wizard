package repohealer

import "testing"

func TestBuildAPTListDoctorActionsBuildsBlockedHashiCorpActionForPinnedKeySuffix(
	t *testing.T,
) {
	result := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		Findings: []Finding{
			{
				Code:     "APT_REPO_KEY_MISSING",
				Evidence: "apt-get update reported NO_PUBKEY FC9CA96ACA026560.",
			},
		},
	}

	references := []APTSourceReference{
		{
			SourceFile:    "/etc/apt/sources.list.d/hashicorp.list",
			LineNumber:    1,
			SourceLine:    "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main",
			RepositoryURL: HashiCorpAPTListRepositoryURL,
			KeyringPath:   HashiCorpAPTListKeyringPath,
			SourceFormat:  SourceFormatAPTList,
		},
	}

	got := BuildAPTListDoctorActions(result, references)

	if len(got) != 1 {
		t.Fatalf("action count = %d, want 1: %#v", len(got), got)
	}

	action := got[0]

	if action.ID != "apt-keyring-repair-hashicorp" {
		t.Fatalf("action ID = %q, want HashiCorp Doctor action ID", action.ID)
	}
	if action.FindingCode != "APT_REPO_KEY_MISSING" {
		t.Fatalf("finding code = %q, want APT_REPO_KEY_MISSING", action.FindingCode)
	}
	if action.Eligible {
		t.Fatal("APT-list Doctor action must remain blocked from repair")
	}
	if action.RequiresConsent {
		t.Fatal("read-only APT-list Doctor action must not request repair consent")
	}
	if action.Risk != RiskBlocked {
		t.Fatalf("risk = %q, want %q", action.Risk, RiskBlocked)
	}
	if action.ProfileID != HashiCorpAPTListProfileID {
		t.Fatalf("profile ID = %q, want %q", action.ProfileID, HashiCorpAPTListProfileID)
	}
	if action.RepositoryURL != HashiCorpAPTListRepositoryURL {
		t.Fatalf("repository URL = %q", action.RepositoryURL)
	}
	if action.SourceFile != "/etc/apt/sources.list.d/hashicorp.list" {
		t.Fatalf("source file = %q", action.SourceFile)
	}
	if action.SourceLine != 1 {
		t.Fatalf("source line = %d, want 1", action.SourceLine)
	}
	if action.SourceFormat != SourceFormatAPTList {
		t.Fatalf("source format = %q, want %q", action.SourceFormat, SourceFormatAPTList)
	}
	if action.KeyringPath != HashiCorpAPTListKeyringPath {
		t.Fatalf("keyring path = %q", action.KeyringPath)
	}
	if len(action.Commands) != 0 ||
		len(action.Verification) != 0 ||
		len(action.Rollback) != 0 {
		t.Fatalf(
			"Doctor-only blocked action must not contain repair commands: %#v",
			action,
		)
	}
	if action.BlockReason == "" {
		t.Fatal("Doctor-only blocked action must explain why it cannot repair")
	}
}

func TestBuildAPTListDoctorActionsRejectsUntrustedOrAmbiguousCandidates(
	t *testing.T,
) {
	baseResult := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			PackageManager: ManagerAPT,
		},
		Findings: []Finding{
			{
				Code:     "APT_REPO_KEY_MISSING",
				Evidence: "apt-get update reported NO_PUBKEY FC9CA96ACA026560.",
			},
		},
	}

	accepted := APTSourceReference{
		SourceFile:    "/etc/apt/sources.list.d/hashicorp.list",
		LineNumber:    1,
		SourceLine:    "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main",
		RepositoryURL: HashiCorpAPTListRepositoryURL,
		KeyringPath:   HashiCorpAPTListKeyringPath,
		SourceFormat:  SourceFormatAPTList,
	}

	tests := []struct {
		name       string
		references []APTSourceReference
	}{
		{
			name: "wrong source format",
			references: []APTSourceReference{
				func() APTSourceReference {
					value := accepted
					value.SourceFormat = SourceFormatDeb822
					return value
				}(),
			},
		},
		{
			name: "wrong source file",
			references: []APTSourceReference{
				func() APTSourceReference {
					value := accepted
					value.SourceFile = "/tmp/hashicorp.list"
					return value
				}(),
			},
		},
		{
			name: "wrong keyring path",
			references: []APTSourceReference{
				func() APTSourceReference {
					value := accepted
					value.KeyringPath = "/tmp/hashicorp.gpg"
					return value
				}(),
			},
		},
		{
			name: "wrong repository URL",
			references: []APTSourceReference{
				func() APTSourceReference {
					value := accepted
					value.RepositoryURL = "https://apt.releases.hashicorp.com.attacker.invalid"
					return value
				}(),
			},
		},
		{
			name: "wrong key suffix",
			references: []APTSourceReference{
				func() APTSourceReference {
					value := accepted
					value.SourceLine = "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main"
					return value
				}(),
			},
		},
		{
			name: "ambiguous distinct candidates",
			references: []APTSourceReference{
				accepted,
				func() APTSourceReference {
					value := accepted
					value.LineNumber = 2
					return value
				}(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := baseResult

			if test.name == "wrong key suffix" {
				result.Findings[0].Evidence =
					"apt-get update reported NO_PUBKEY 0000000000000000."
			}

			if got := BuildAPTListDoctorActions(result, test.references); len(got) != 0 {
				t.Fatalf("action count = %d, want 0: %#v", len(got), got)
			}
		})
	}
}

func TestBuildAPTListDoctorActionsIgnoresNonMissingKeyFindings(t *testing.T) {
	result := Result{
		Findings: []Finding{
			{
				Code:     "APT_KEYRING_PATH_MISSING",
				Evidence: "Repository configuration references a missing keyring.",
			},
		},
	}

	references := []APTSourceReference{
		{
			SourceFile:    "/etc/apt/sources.list.d/hashicorp.list",
			LineNumber:    1,
			SourceLine:    "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main",
			RepositoryURL: HashiCorpAPTListRepositoryURL,
			KeyringPath:   HashiCorpAPTListKeyringPath,
			SourceFormat:  SourceFormatAPTList,
		},
	}

	if got := BuildAPTListDoctorActions(result, references); len(got) != 0 {
		t.Fatalf("action count = %d, want 0: %#v", len(got), got)
	}
}
