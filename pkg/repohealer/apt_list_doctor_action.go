package repohealer

import (
	"fmt"
	"regexp"
	"strings"
)

var aptNoPubKeyEvidencePattern = regexp.MustCompile(
	`(?i)\bNO_PUBKEY\s+([A-F0-9]{16})\b`,
)

func BuildAPTListDoctorActions(
	result Result,
	references []APTSourceReference,
) []RepairAction {
	actions := make([]RepairAction, 0)

	for _, finding := range result.Findings {
		if finding.Code != "APT_REPO_KEY_MISSING" {
			continue
		}

		keyID, ok := missingAPTKeyIDFromEvidence(finding.Evidence)
		if !ok {
			continue
		}

		candidates := matchingAPTListDoctorCandidates(keyID, references)
		if len(candidates) != 1 {
			continue
		}

		candidate := candidates[0]
		profile := candidate.profile
		reference := candidate.reference

		actions = append(actions, RepairAction{
			ID:          "apt-keyring-repair-" + profile.ID,
			FindingCode: finding.Code,
			Risk:        RiskBlocked,
			Description: fmt.Sprintf(
				"Read-only APT-list Doctor is available for the blocked %s repository key failure.",
				profile.DisplayName,
			),
			Commands:        nil,
			Verification:    nil,
			Rollback:        nil,
			RequiresConsent: false,
			Eligible:        false,
			BlockReason: fmt.Sprintf(
				"Repair is blocked: apt-get update reported missing signing key %s. Run the read-only APT-list Doctor before any repair workflow.",
				keyID,
			),
			ProfileID:            profile.ID,
			ProfileDisplayName:   profile.DisplayName,
			RepositoryURL:        reference.RepositoryURL,
			Target:               result.Target,
			KeyURL:               profile.KeyURL,
			ExpectedFingerprints: append([]string(nil), profile.ExpectedFingerprints...),
			KeyringPath:          reference.KeyringPath,
			SourceFile:           reference.SourceFile,
			SourceLine:           reference.LineNumber,
			SourceFormat:         reference.SourceFormat,
			SnapshotTargets:      nil,
		})
	}

	return actions
}

type aptListDoctorCandidate struct {
	profile   VendorProfile
	reference APTSourceReference
}

func matchingAPTListDoctorCandidates(
	keyID string,
	references []APTSourceReference,
) []aptListDoctorCandidate {
	candidates := make([]aptListDoctorCandidate, 0)
	seen := make(map[string]bool)

	for _, reference := range references {
		if reference.SourceFormat != SourceFormatAPTList {
			continue
		}

		profile, ok := FindVendorProfile(
			ManagerAPT,
			reference.RepositoryURL,
		)
		if !ok || profile.ID != HashiCorpAPTListProfileID {
			continue
		}

		if reference.SourceFile != profile.SourceFile ||
			reference.KeyringPath != profile.KeyringPath {
			continue
		}

		if !profileHasFingerprintSuffix(profile, keyID) {
			continue
		}

		identity := fmt.Sprintf(
			"%s|%d|%s|%s|%s",
			reference.SourceFile,
			reference.LineNumber,
			reference.RepositoryURL,
			reference.KeyringPath,
			profile.ID,
		)
		if seen[identity] {
			continue
		}
		seen[identity] = true

		candidates = append(candidates, aptListDoctorCandidate{
			profile:   profile,
			reference: reference,
		})
	}

	return candidates
}

func missingAPTKeyIDFromEvidence(evidence string) (string, bool) {
	match := aptNoPubKeyEvidencePattern.FindStringSubmatch(evidence)
	if len(match) != 2 {
		return "", false
	}

	keyID := strings.ToUpper(strings.TrimSpace(match[1]))
	if len(keyID) != 16 {
		return "", false
	}

	return keyID, true
}

func profileHasFingerprintSuffix(
	profile VendorProfile,
	keyID string,
) bool {
	keyID = strings.ToUpper(strings.TrimSpace(keyID))

	for _, fingerprint := range profile.ExpectedFingerprints {
		normalized := strings.ToUpper(
			strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""),
		)
		if len(normalized) >= len(keyID) &&
			strings.HasSuffix(normalized, keyID) {
			return true
		}
	}

	return false
}
