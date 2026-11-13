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

	case "postgresql-pgdg":
		suite, err := ResolveCodenameSuite(profile, input)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf(
			"deb [arch=%s signed-by=%s] %s %s %s",
			architecture,
			profile.KeyringPath,
			profile.AllowedURLPrefixes[0],
			suite,
			profile.Components,
		), nil

	case "jenkins":
		// Jenkins publishes a "flat" repository (no Suites/Components split): a single
		// directory URL with a trailing slash, and no arch= directive in its documented line.
		return fmt.Sprintf(
			"deb [signed-by=%s] %s %s",
			profile.KeyringPath,
			profile.AllowedURLPrefixes[0],
			profile.Suite,
		), nil

	default:
		if profile.Suite != "" && profile.Components != "" {
			return fmt.Sprintf(
				"deb [arch=%s signed-by=%s] %s %s %s",
				architecture,
				profile.KeyringPath,
				profile.AllowedURLPrefixes[0],
				profile.Suite,
				profile.Components,
			), nil
		}
		return "", fmt.Errorf("no APT source renderer is implemented for profile %q", profile.ID)
	}
}

func RenderAPTDeb822Source(profile VendorProfile, input SourceRenderInput) (string, error) {
	if profile.PackageManager != ManagerAPT {
		return "", fmt.Errorf("profile %q is not an APT profile", profile.ID)
	}

	architecture := strings.TrimSpace(input.Architecture)
	if architecture == "" {
		return "", fmt.Errorf("cannot render %q Deb822 APT source: target architecture is empty", profile.ID)
	}

	switch profile.ID {
	case "microsoft-vscode":
		return fmt.Sprintf(
			"Types: deb\n"+
				"URIs: %s\n"+
				"Suites: stable\n"+
				"Components: main\n"+
				"Architectures: %s\n"+
				"Signed-By: %s\n",
			profile.AllowedURLPrefixes[0],
			architecture,
			profile.KeyringPath,
		), nil

	case "docker-ce":
		suite, err := ResolveDockerDebianSuite(input)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf(
			"Types: deb\n"+
				"URIs: %s\n"+
				"Suites: %s\n"+
				"Components: stable\n"+
				"Architectures: %s\n"+
				"Signed-By: %s\n",
			profile.AllowedURLPrefixes[0],
			suite,
			architecture,
			profile.KeyringPath,
		), nil

	case "postgresql-pgdg":
		suite, err := ResolveCodenameSuite(profile, input)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf(
			"Types: deb\n"+
				"URIs: %s\n"+
				"Suites: %s\n"+
				"Components: %s\n"+
				"Architectures: %s\n"+
				"Signed-By: %s\n",
			profile.AllowedURLPrefixes[0],
			suite,
			profile.Components,
			architecture,
			profile.KeyringPath,
		), nil

	default:
		if profile.Suite != "" && profile.Components != "" {
			return fmt.Sprintf(
				"Types: deb\n"+
					"URIs: %s\n"+
					"Suites: %s\n"+
					"Components: %s\n"+
					"Architectures: %s\n"+
					"Signed-By: %s\n",
				profile.AllowedURLPrefixes[0],
				profile.Suite,
				profile.Components,
				architecture,
				profile.KeyringPath,
			), nil
		}
		return "", fmt.Errorf("no Deb822 APT source renderer is implemented for profile %q", profile.ID)
	}
}

// ResolveCodenameSuite resolves a vendor profile whose suite is the target's own distro
// codename plus a fixed suffix (e.g. PostgreSQL PGDG's "<codename>-pgdg"), restricted to the
// codenames that vendor documents support. Unlike ResolveDockerDebianSuite (which maps a
// codename to a different, fixed upstream suite name), this one just validates the codename
// against the documented support list and appends the suffix — no renaming.
func ResolveCodenameSuite(profile VendorProfile, input SourceRenderInput) (string, error) {
	codename := strings.ToLower(strings.TrimSpace(input.Codename))

	for _, supported := range profile.SupportedCodenames {
		if codename == supported {
			return codename + profile.CodenameSuiteSuffix, nil
		}
	}

	return "", fmt.Errorf(
		"%s suite review required: unsupported codename %q (supported: %s)",
		profile.DisplayName,
		codename,
		strings.Join(profile.SupportedCodenames, ", "),
	)
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
