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
			KeyURL:               "https://packages.microsoft.com/keys/microsoft.asc",
			KeyringPath:          "/etc/apt/keyrings/microsoft.gpg",
			ExpectedFingerprints: []string{},
			SourceFile:           "/etc/apt/sources.list.d/vscode.list",
			SourceLine:           "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main",
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
