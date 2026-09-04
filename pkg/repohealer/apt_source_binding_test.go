package repohealer

import "testing"

func TestHasExpectedAPTKeyringBindingAcceptsDockerProfileKeyring(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	sourceLine := "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable"

	if !HasExpectedAPTKeyringBinding(profile, sourceLine) {
		t.Fatal("Docker source line with Docker keyring must match profile binding")
	}
}

func TestHasExpectedAPTKeyringBindingRejectsWrongDockerKeyring(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	sourceLine := "deb [arch=amd64 signed-by=/etc/apt/keyrings/old-docker.gpg] https://download.docker.com/linux/debian bookworm stable"

	if HasExpectedAPTKeyringBinding(profile, sourceLine) {
		t.Fatal("Docker source line with a different keyring must not match profile binding")
	}
}

func TestHasExpectedAPTKeyringBindingRejectsMissingSignedBy(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	sourceLine := "deb [arch=amd64] https://download.docker.com/linux/debian bookworm stable"

	if HasExpectedAPTKeyringBinding(profile, sourceLine) {
		t.Fatal("Docker source line without signed-by must not match profile binding")
	}
}

func TestHasExpectedAPTKeyringBindingAcceptsDeb822SignedByField(t *testing.T) {
	profile, ok := FindVendorProfile(
		ManagerAPT,
		"https://download.docker.com/linux/debian",
	)
	if !ok {
		t.Fatal("expected Docker profile")
	}

	sourceEntry := `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg`

	if !HasExpectedAPTKeyringBinding(profile, sourceEntry) {
		t.Fatal("deb822 Signed-By field with Docker keyring must match profile binding")
	}
}
