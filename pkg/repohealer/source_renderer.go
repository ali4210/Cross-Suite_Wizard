package repohealer

import (
	"fmt"
	"strings"
)

type SourceRenderInput struct {
	Architecture string
	Distribution string
	Version      string
	Codename     string
}

func RenderAPTSource(profile VendorProfile, input SourceRenderInput) (string, error) {
	if profile.PackageManager != ManagerAPT {
		return "", fmt.Errorf("profile %q is not an APT profile", profile.ID)
	}

	architecture := strings.TrimSpace(input.Architecture)
	if architecture == "" {
		return "", fmt.Errorf("cannot render %q APT source: target architecture is empty", profile.ID)
	}

	switch profile.ID {
	case "microsoft-vscode":
		return fmt.Sprintf(
			"deb [arch=%s signed-by=%s] %s stable main",
			architecture,
			profile.KeyringPath,
			profile.AllowedURLPrefixes[0],
		), nil

	case "docker-ce":
		suite, err := ResolveDockerDebianSuite(input)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf(
			"deb [arch=%s signed-by=%s] %s %s stable",
			architecture,
			profile.KeyringPath,
			profile.AllowedURLPrefixes[0],
			suite,
		), nil

	default:
		return "", fmt.Errorf("no APT source renderer is implemented for profile %q", profile.ID)
	}
}

func ResolveDockerDebianSuite(input SourceRenderInput) (string, error) {
	distribution := strings.ToLower(strings.TrimSpace(input.Distribution))
	version := strings.TrimSpace(input.Version)
	codename := strings.ToLower(strings.TrimSpace(input.Codename))

	// Parrot Security 6.4 (Lorikeet) identifies itself as Debian with
	// VERSION_CODENAME=lory. Its Docker CE repository must use Debian 12 Bookworm.
	if distribution == "debian" && version == "6.4" && codename == "lory" {
		return "bookworm", nil
	}

	if distribution == "debian" {
		switch codename {
		case "bookworm", "bullseye", "trixie":
			return codename, nil
		default:
			return "", fmt.Errorf(
				"Docker Debian suite review required: unsupported Debian codename %q",
				codename,
			)
		}
	}

	if distribution == "parrot" {
		switch codename {
		case "lory":
			return "bookworm", nil
		default:
			return "", fmt.Errorf(
				"Docker Parrot suite review required: unsupported Parrot codename %q",
				codename,
			)
		}
	}

	return "", fmt.Errorf(
		"Docker APT repair is not approved for distribution %q",
		distribution,
	)
}
