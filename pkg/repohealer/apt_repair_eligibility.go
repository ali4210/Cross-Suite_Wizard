package repohealer

func IsKnownAPTRepairFinding(code string) bool {
	switch code {
	case "APT_KEYRING_PATH_MISSING", "APT_SOURCE_KEYRING_MISMATCH":
		return true
	default:
		return false
	}
}

func APTRepairActionID(profileID, findingCode string) string {
	switch findingCode {
	case "APT_KEYRING_PATH_MISSING":
		return "apt-keyring-repair-" + profileID
	case "APT_SOURCE_KEYRING_MISMATCH":
		return "apt-source-binding-repair-" + profileID
	default:
		return ""
	}
}
