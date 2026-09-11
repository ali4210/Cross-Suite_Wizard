package repohealer

import (
	"fmt"
	"strings"
)

type Deb822DocumentValidation struct {
	Valid         bool
	Reason        string
	StanzaCount   int
	RepositoryURL string
	KeyringPath   string
	Architecture  string
}

func ValidateSingleProfileDeb822Document(
	document string,
	profile VendorProfile,
) Deb822DocumentValidation {
	stanzas := splitDeb822DocumentStanzas(document)

	result := Deb822DocumentValidation{
		StanzaCount: len(stanzas),
	}

	if len(stanzas) == 0 {
		result.Reason = "Deb822 source document contains no non-comment stanzas."
		return result
	}

	if len(stanzas) != 1 {
		result.Reason = fmt.Sprintf(
			"Deb822 source document contains %d non-comment stanzas; only one profile-owned stanza can be replaced safely.",
			len(stanzas),
		)
		return result
	}

	fields, reason := parseSingleDeb822Stanza(stanzas[0])
	if reason != "" {
		result.Reason = reason
		return result
	}

	for _, required := range []string{
		"types",
		"uris",
		"suites",
		"components",
		"signed-by",
	} {
		if _, ok := fields[required]; !ok {
			result.Reason = fmt.Sprintf(
				"Deb822 source document is missing required field %q.",
				deb822DisplayFieldName(required),
			)
			return result
		}
	}

	if fields["types"] != "deb" {
		result.Reason = fmt.Sprintf(
			"Deb822 Types must be exactly %q, got %q.",
			"deb",
			fields["types"],
		)
		return result
	}

	repositoryURL := fields["uris"]
	if len(strings.Fields(repositoryURL)) != 1 {
		result.Reason = "Deb822 URIs must contain exactly one repository URL."
		return result
	}

	if !isValidAPTRepositoryURL(repositoryURL) {
		result.Reason = "Deb822 URIs must contain one plain HTTPS repository URL."
		return result
	}

	if !profileAllowsExactRepositoryURL(profile, repositoryURL) {
		result.Reason = fmt.Sprintf(
			"Deb822 URI %q is not an exact allowlisted repository URL for profile %q.",
			repositoryURL,
			profile.ID,
		)
		return result
	}

	keyringPath := fields["signed-by"]
	if len(strings.Fields(keyringPath)) != 1 {
		result.Reason = "Deb822 Signed-By must contain exactly one keyring path."
		return result
	}

	if keyringPath != profile.KeyringPath {
		result.Reason = fmt.Sprintf(
			"Deb822 Signed-By path %q does not match profile keyring %q.",
			keyringPath,
			profile.KeyringPath,
		)
		return result
	}

	architecture := ""
	if value, ok := fields["architectures"]; ok {
		if len(strings.Fields(value)) != 1 {
			result.Reason = "Deb822 Architectures must contain exactly one architecture token when present."
			return result
		}
		architecture = value
	}

	result.Valid = true
	result.RepositoryURL = repositoryURL
	result.KeyringPath = keyringPath
	result.Architecture = architecture

	return result
}

func splitDeb822DocumentStanzas(document string) []string {
	document = strings.ReplaceAll(document, "\r\n", "\n")
	document = strings.ReplaceAll(document, "\r", "\n")

	var stanzas []string
	var current []string

	flush := func() {
		if len(current) == 0 {
			return
		}

		stanzas = append(stanzas, strings.Join(current, "\n"))
		current = nil
	}

	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if trimmed == "" {
			flush()
			continue
		}

		current = append(current, line)
	}

	flush()

	return stanzas
}

func parseSingleDeb822Stanza(stanza string) (map[string]string, string) {
	fields := make(map[string]string)

	for _, line := range strings.Split(stanza, "\n") {
		separator := strings.Index(line, ":")
		if separator < 1 {
			return nil, fmt.Sprintf(
				"Deb822 stanza contains malformed field line %q.",
				line,
			)
		}

		name := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+1:])

		if name == "" || value == "" {
			return nil, fmt.Sprintf(
				"Deb822 stanza contains malformed field line %q.",
				line,
			)
		}

		if _, exists := fields[name]; exists {
			return nil, fmt.Sprintf(
				"Deb822 stanza repeats field %q.",
				deb822DisplayFieldName(name),
			)
		}

		fields[name] = value
	}

	return fields, ""
}

func profileAllowsExactRepositoryURL(profile VendorProfile, repositoryURL string) bool {
	for _, allowed := range profile.AllowedURLPrefixes {
		if repositoryURL == allowed {
			return true
		}
	}

	return false
}

func deb822DisplayFieldName(name string) string {
	switch name {
	case "types":
		return "Types"
	case "uris":
		return "URIs"
	case "suites":
		return "Suites"
	case "components":
		return "Components"
	case "architectures":
		return "Architectures"
	case "signed-by":
		return "Signed-By"
	default:
		return name
	}
}
