package playbook

import (
	"testing"

	"cross-ssh/pkg/repohealer"
)

func TestBlockedDeb822DoctorActionsReturnsOnlyVerifiedBlockedDeb822Actions(
	t *testing.T,
) {
	accepted := blockedDockerDeb822PlaybookAction()

	eligibleDeb822 := accepted
	eligibleDeb822.ID = "eligible-deb822"
	eligibleDeb822.Eligible = true
	eligibleDeb822.RequiresConsent = true

	consentBearingDeb822 := accepted
	consentBearingDeb822.ID = "consent-bearing-deb822"
	consentBearingDeb822.RequiresConsent = true

	classicList := accepted
	classicList.ID = "classic-list"
	classicList.SourceFormat = repohealer.SourceFormatAPTList

	unknownProfile := accepted
	unknownProfile.ID = "unknown-profile"
	unknownProfile.ProfileID = "unknown"
	unknownProfile.RepositoryURL = "https://unknown.example.invalid/apt"

	got := blockedDeb822DoctorActions([]repohealer.RepairAction{
		eligibleDeb822,
		consentBearingDeb822,
		classicList,
		unknownProfile,
		accepted,
	})

	if len(got) != 1 {
		t.Fatalf("eligible action count = %d, want 1: %#v", len(got), got)
	}
	if got[0].ID != accepted.ID {
		t.Fatalf("selected action ID = %q, want %q", got[0].ID, accepted.ID)
	}
}

func TestBlockedDeb822DoctorActionsReturnsEmptyForNoEligibleActions(
	t *testing.T,
) {
	if got := blockedDeb822DoctorActions(nil); len(got) != 0 {
		t.Fatalf("eligible actions = %#v, want none", got)
	}
}
