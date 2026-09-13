package repohealer

import (
	"strings"
	"testing"
)

func TestFormatAPTListDoctorReport(t *testing.T) {
	report := APTListDoctorReport{
		Overall: APTListDoctorStatusBlocked,
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		ActionID:            "apt-keyring-repair-hashicorp",
		ProfileID:           HashiCorpAPTListProfileID,
		RepositoryURL:       HashiCorpAPTListRepositoryURL,
		SourceFile:          "/etc/apt/sources.list.d/hashicorp.list",
		SourceLine:          1,
		KeyringPath:         HashiCorpAPTListKeyringPath,
		ExpectedFingerprint: HashiCorpAPTListExpectedFingerprint,
		Checks: []APTListDoctorCheck{
			{
				Name:    "expected_signing_key",
				Status:  APTListDoctorStatusBlocked,
				Message: "Expected HashiCorp signing key is absent.",
			},
		},
	}

	got := FormatAPTListDoctorReport(report)

	for _, want := range []string{
		"Repo Healer APT List Readiness Report",
		"Overall: blocked",
		"Distribution: debian",
		"Profile ID: hashicorp",
		"Source file: /etc/apt/sources.list.d/hashicorp.list",
		"Keyring path: /usr/share/keyrings/hashicorp-archive-keyring.gpg",
		"Expected fingerprint: D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
		"Permissions: inspect=false preview=false apply=false",
		"[blocked] expected_signing_key: Expected HashiCorp signing key is absent.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted report missing %q:\n%s", want, got)
		}
	}
}

func TestFormatAPTListDoctorReportShowsEmptyChecks(t *testing.T) {
	got := FormatAPTListDoctorReport(APTListDoctorReport{})

	if !strings.Contains(got, "Checks:\n- none\n") {
		t.Fatalf("formatted report did not render empty checks:\n%s", got)
	}
}
