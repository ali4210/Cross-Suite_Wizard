package repohealer

import "strings"

// HashiCorpAPTListRepairSafety captures the non-repository blockers that must be clear before
// the HashiCorp APT-list keyring repair is allowed to apply: low disk space, suspected clock
// skew (both of which make TLS/GPG verification unreliable), and a dpkg database that is not
// healthy enough for apt-get update to run safely. All three are read-only checks; none of them
// change the target.
type HashiCorpAPTListRepairSafety struct {
	DiskSpaceLow       bool
	DiskEvidence       string
	ClockSkewSuspected bool
	ClockEvidence      string
	DpkgBroken         bool
	DpkgAuditOutput    string
}

// EvaluateHashiCorpAPTListRepairSafety runs the same read-only network/disk/clock pre-checks
// every adapter already relies on (CollectNetworkFacts), plus a dedicated dpkg --audit probe,
// and folds the results into a single safety gate for the apply step.
func EvaluateHashiCorpAPTListRepairSafety(exec Executor) HashiCorpAPTListRepairSafety {
	var safety HashiCorpAPTListRepairSafety

	_, findings := CollectNetworkFacts(exec)
	for _, finding := range findings {
		switch finding.Code {
		case "NETWORK_DISK_SPACE_LOW":
			safety.DiskSpaceLow = true
			safety.DiskEvidence = finding.Evidence
		case "NETWORK_CLOCK_SKEW_SUSPECTED":
			safety.ClockSkewSuspected = true
			safety.ClockEvidence = finding.Evidence
		}
	}

	output, err := exec.RunSudo("set +e\ndpkg --audit 2>&1\n")
	if err == nil {
		trimmed := strings.TrimSpace(output)
		if trimmed != "" {
			safety.DpkgBroken = true
			safety.DpkgAuditOutput = trimmed
		}
	}

	return safety
}

// Blocked reports whether the safety gate forbids applying the repair, and a plain-language
// explanation (reason) plus the next step the operator should take.
func (s HashiCorpAPTListRepairSafety) Blocked() (bool, string) {
	switch {
	case s.DiskSpaceLow:
		return true, "BLOCKED: the root filesystem is at or near capacity (" + s.DiskEvidence +
			"). Next step: free up space (apt-get clean, remove old logs) and re-run this repair; " +
			"package downloads and atomic installs fail unpredictably when the disk is full."
	case s.ClockSkewSuspected:
		return true, "BLOCKED: the target host's clock appears to be significantly out of sync (" +
			s.ClockEvidence + "). Next step: fix NTP/time sync on the target before retrying; " +
			"TLS and GPG signature verification can fail, or falsely succeed, with a skewed clock."
	case s.DpkgBroken:
		return true, "BLOCKED: dpkg --audit reports broken or inconsistent packages, so apt-get update " +
			"cannot safely run:\n" + s.DpkgAuditOutput +
			"\nNext step: review the packages above, then use the gated 'apt --fix-broken install' " +
			"repair (Option 7) before retrying this repair."
	default:
		return false, ""
	}
}
