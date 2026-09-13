package repohealer

import "testing"

func TestHashiCorpVendorProfile(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://apt.releases.hashicorp.com",
	)
	if !ok {
		t.Fatal("expected HashiCorp vendor profile to be found")
	}

	if profile.ID != HashiCorpAPTListProfileID {
		t.Fatalf(
			"profile ID = %q, want %q",
			profile.ID,
			HashiCorpAPTListProfileID,
		)
	}
	if profile.DisplayName != "HashiCorp" {
		t.Fatalf("display name = %q", profile.DisplayName)
	}
	if profile.KeyURL != "https://apt.releases.hashicorp.com/gpg" {
		t.Fatalf("key URL = %q", profile.KeyURL)
	}
	if profile.KeyringPath != HashiCorpAPTListKeyringPath {
		t.Fatalf(
			"keyring path = %q, want %q",
			profile.KeyringPath,
			HashiCorpAPTListKeyringPath,
		)
	}
	if profile.SourceFile != "/etc/apt/sources.list.d/hashicorp.list" {
		t.Fatalf("source file = %q", profile.SourceFile)
	}

	if len(profile.ExpectedFingerprints) != 1 {
		t.Fatalf(
			"expected fingerprint count = %d, want 1",
			len(profile.ExpectedFingerprints),
		)
	}
	if !IsPinnedFingerprint(
		profile,
		HashiCorpAPTListExpectedFingerprint,
	) {
		t.Fatalf(
			"HashiCorp profile does not pin expected fingerprint %q",
			HashiCorpAPTListExpectedFingerprint,
		)
	}

	byID, ok := FindVendorProfileByID(
		ManagerAPT,
		HashiCorpAPTListProfileID,
	)
	if !ok {
		t.Fatal("expected HashiCorp vendor profile to be found by ID")
	}
	if byID.ID != profile.ID ||
		byID.DisplayName != profile.DisplayName ||
		byID.PackageManager != profile.PackageManager ||
		byID.KeyURL != profile.KeyURL ||
		byID.KeyringPath != profile.KeyringPath ||
		byID.SourceFile != profile.SourceFile ||
		byID.SourceLine != profile.SourceLine {
		t.Fatalf("profile lookup by ID = %#v, want %#v", byID, profile)
	}

	if len(byID.AllowedURLPrefixes) != len(profile.AllowedURLPrefixes) {
		t.Fatalf(
			"allowed URL prefix count = %d, want %d",
			len(byID.AllowedURLPrefixes),
			len(profile.AllowedURLPrefixes),
		)
	}
	for index := range profile.AllowedURLPrefixes {
		if byID.AllowedURLPrefixes[index] != profile.AllowedURLPrefixes[index] {
			t.Fatalf(
				"allowed URL prefix %d = %q, want %q",
				index,
				byID.AllowedURLPrefixes[index],
				profile.AllowedURLPrefixes[index],
			)
		}
	}

	if len(byID.ExpectedFingerprints) != len(profile.ExpectedFingerprints) {
		t.Fatalf(
			"expected fingerprint count = %d, want %d",
			len(byID.ExpectedFingerprints),
			len(profile.ExpectedFingerprints),
		)
	}
	for index := range profile.ExpectedFingerprints {
		if byID.ExpectedFingerprints[index] !=
			profile.ExpectedFingerprints[index] {
			t.Fatalf(
				"expected fingerprint %d = %q, want %q",
				index,
				byID.ExpectedFingerprints[index],
				profile.ExpectedFingerprints[index],
			)
		}
	}
}

func TestHashiCorpVendorProfileURLBoundaries(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "Exact repository URL",
			url:  "https://apt.releases.hashicorp.com",
			want: true,
		},
		{
			name: "Repository URL with trailing slash",
			url:  "https://apt.releases.hashicorp.com/",
			want: true,
		},
		{
			name: "Repository URL with allowed path",
			url:  "https://apt.releases.hashicorp.com/dists/bookworm",
			want: true,
		},
		{
			name: "Lookalike host suffix",
			url:  "https://apt.releases.hashicorp.com.attacker.invalid",
			want: false,
		},
		{
			name: "Lookalike path without separator",
			url:  "https://apt.releases.hashicorp.com.attacker/path",
			want: false,
		},
		{
			name: "Different scheme",
			url:  "http://apt.releases.hashicorp.com",
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, ok := FindVendorProfile(ManagerAPT, test.url)

			if ok != test.want {
				t.Fatalf(
					"FindVendorProfile(%q) found=%t, want %t",
					test.url,
					ok,
					test.want,
				)
			}

			if ok && profile.ID != HashiCorpAPTListProfileID {
				t.Fatalf(
					"matched profile ID = %q, want %q",
					profile.ID,
					HashiCorpAPTListProfileID,
				)
			}
		})
	}
}
