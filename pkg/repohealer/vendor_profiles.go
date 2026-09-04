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
		},
	}
}

func FindVendorProfile(manager PackageManager, repositoryURL string) (VendorProfile, bool) {
	for _, profile := range KnownVendorProfiles() {
		if profile.PackageManager != manager {
			continue
		}

		for _, prefix := range profile.AllowedURLPrefixes {
			if strings.HasPrefix(repositoryURL, prefix) {
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
