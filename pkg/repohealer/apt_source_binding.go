package repohealer

import "strings"

func HasExpectedAPTKeyringBinding(profile VendorProfile, sourceLine string) bool {
	expected := strings.TrimSpace(profile.KeyringPath)
	if expected == "" {
		return false
	}

	lowerLine := strings.ToLower(sourceLine)
	lowerExpected := strings.ToLower(expected)

	return strings.Contains(lowerLine, "signed-by="+lowerExpected) ||
		strings.Contains(lowerLine, "signed-by = "+lowerExpected) ||
		strings.Contains(lowerLine, "signed-by:"+lowerExpected) ||
		strings.Contains(lowerLine, "signed-by: "+lowerExpected)
}
