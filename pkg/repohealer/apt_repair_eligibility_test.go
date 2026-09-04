package repohealer

import "testing"

func TestIsKnownAPTRepairFinding(t *testing.T) {
	for _, code := range []string{
		"APT_KEYRING_PATH_MISSING",
		"APT_SOURCE_KEYRING_MISMATCH",
	} {
		if !IsKnownAPTRepairFinding(code) {
			t.Fatalf("finding code %q must be eligible for known APT repair planning", code)
		}
	}

	for _, code := range []string{
		"",
		"APT_REPO_KEY_MISSING",
		"APT_REPO_DNS_FAILURE",
		"APT_REPO_TLS_FAILURE",
		"APT_LOCK_ACTIVE",
	} {
		if IsKnownAPTRepairFinding(code) {
			t.Fatalf("finding code %q must not be eligible for known APT repair planning", code)
		}
	}
}

func TestAPTRepairActionID(t *testing.T) {
	tests := []struct {
		profileID   string
		findingCode string
		want        string
	}{
		{
			profileID:   "docker-ce",
			findingCode: "APT_KEYRING_PATH_MISSING",
			want:        "apt-keyring-repair-docker-ce",
		},
		{
			profileID:   "docker-ce",
			findingCode: "APT_SOURCE_KEYRING_MISMATCH",
			want:        "apt-source-binding-repair-docker-ce",
		},
		{
			profileID:   "docker-ce",
			findingCode: "APT_REPO_DNS_FAILURE",
			want:        "",
		},
	}

	for _, tt := range tests {
		if got := APTRepairActionID(tt.profileID, tt.findingCode); got != tt.want {
			t.Fatalf(
				"APTRepairActionID(%q, %q) = %q, want %q",
				tt.profileID,
				tt.findingCode,
				got,
				tt.want,
			)
		}
	}
}
