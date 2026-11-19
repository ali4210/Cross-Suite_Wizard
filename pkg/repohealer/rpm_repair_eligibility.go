package repohealer

// IsKnownRPMRepairFinding mirrors IsKnownAPTRepairFinding for the dnf/yum/zypper family:
// only a repository whose key/trust is broken (not an unrelated metadata-cache or rpmdb
// finding, which dnf.go/zypper.go already repair on their own) is eligible for the
// known-vendor key-import repair.
func IsKnownRPMRepairFinding(code string) bool {
	switch code {
	case "DNF_REPO_GPG_FAILURE", "ZYPPER_REPO_GPG_FAILURE":
		return true
	default:
		return false
	}
}

// RPMRepairActionID mirrors APTRepairActionID.
func RPMRepairActionID(profileID, findingCode string) string {
	switch findingCode {
	case "DNF_REPO_GPG_FAILURE", "ZYPPER_REPO_GPG_FAILURE":
		return "rpm-key-repair-" + profileID
	default:
		return ""
	}
}
