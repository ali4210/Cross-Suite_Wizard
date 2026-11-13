package repohealer

import (
	"fmt"
	"os"
	"strings"
)

// PreviewCustomRepositoryKeyFingerprint downloads a candidate signing key from the given HTTPS
// URL — read-only, no system file is created or modified — and returns its single full
// fingerprint for the operator to manually verify against the repository's own official
// documentation before typing it back to confirm. This is the "confirm-the-fingerprint" path
// for a repository with no known VendorProfile: unlike the pinned-fingerprint vendors, there is
// nothing in this codebase that can verify the key is correct, so the human operator is the
// verification step.
//
// It requires the URL to be HTTPS (never a keyserver), and requires the downloaded file to
// contain exactly one OpenPGP key. A bundle of multiple keys is rejected rather than guessed
// at, since there would be no way to tell which one is the repository's real signing key.
func PreviewCustomRepositoryKeyFingerprint(exec Executor, keyURL string) (string, error) {
	trimmed := strings.TrimSpace(keyURL)
	if !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		return "", fmt.Errorf("key URL %q must be HTTPS", keyURL)
	}

	script := fmt.Sprintf(`set -eu
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 %s -o "$TMP/key.asc"
test -s "$TMP/key.asc"

gpg --show-keys --with-colons --fingerprint "$TMP/key.asc" 2>/dev/null \
	| awk -F: '$1 == "fpr" {print toupper($10)}' \
	| sort -u
`, shellSingleQuote(trimmed))

	out, err := exec.Run(script)
	if err != nil {
		return "", fmt.Errorf("could not download or parse the key at %q: %w: %s", keyURL, err, strings.TrimSpace(out))
	}

	var fingerprints []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			fingerprints = append(fingerprints, line)
		}
	}

	switch len(fingerprints) {
	case 0:
		return "", fmt.Errorf("no OpenPGP fingerprint was found in the key downloaded from %q", keyURL)
	case 1:
		return fingerprints[0], nil
	default:
		return "", fmt.Errorf(
			"the key downloaded from %q bundles %d fingerprints; confirm-the-fingerprint mode requires a single-key file (ask the vendor for a dedicated key, or use a known vendor profile instead)",
			keyURL,
			len(fingerprints),
		)
	}
}

// NormalizeFingerprint upper-cases and strips whitespace from a fingerprint, the same way
// IsPinnedFingerprint does for a pinned vendor profile, so a typed confirmation can be compared
// against a downloaded one regardless of case or spacing.
func NormalizeFingerprint(fingerprint string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""))
}

// EvaluateGatedAPTRepairSafety is a generic name for EvaluateHashiCorpAPTListRepairSafety's
// disk/clock/dpkg checks, which are not actually HashiCorp-specific — that function predates
// their reuse by other gated APT repairs. New gated flows should call this one; existing
// callers are unaffected.
func EvaluateGatedAPTRepairSafety(exec Executor) HashiCorpAPTListRepairSafety {
	return EvaluateHashiCorpAPTListRepairSafety(exec)
}

// CustomKeyRepairExecutionEnabledEnv is the operator-policy environment variable that must be
// set to exactly "true" before a confirm-the-fingerprint custom repository key is allowed to be
// installed. Exported so callers (e.g. the playbook UI) can show the exact variable name.
const CustomKeyRepairExecutionEnabledEnv = "CROSS_SUITE_CUSTOMKEY_REPAIR_ENABLED"

// CustomKeyRepairExecutionEnabled mirrors the other gated repairs' operator-policy gate.
func CustomKeyRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(CustomKeyRepairExecutionEnabledEnv)),
		"true",
	)
}
