package repohealer

import "testing"

func TestIsRepairApprovedAcceptsExplicitYesForEligibleConsentAction(t *testing.T) {
	action := RepairAction{
		Eligible:        true,
		RequiresConsent: true,
	}

	for _, response := range []string{
		"y",
		"Y",
		"yes",
		"YES",
		" Yes ",
		"\ty\t",
	} {
		if !IsRepairApproved(action, response) {
			t.Fatalf("response %q must approve an eligible consent action", response)
		}
	}
}

func TestIsRepairApprovedRejectsNonApprovalResponses(t *testing.T) {
	action := RepairAction{
		Eligible:        true,
		RequiresConsent: true,
	}

	for _, response := range []string{
		"",
		" ",
		"n",
		"N",
		"no",
		"NO",
		"0",
		"q",
		"back",
		"approve",
		"true",
		"yess",
	} {
		if IsRepairApproved(action, response) {
			t.Fatalf("response %q must not approve a repair", response)
		}
	}
}

func TestIsRepairApprovedRejectsBlockedActionEvenWithYes(t *testing.T) {
	action := RepairAction{
		Eligible:        false,
		RequiresConsent: true,
	}

	for _, response := range []string{"y", "yes", "YES"} {
		if IsRepairApproved(action, response) {
			t.Fatalf("blocked action must not be approved by response %q", response)
		}
	}
}

func TestIsRepairApprovedRejectsActionWithoutConsentRequirement(t *testing.T) {
	action := RepairAction{
		Eligible:        true,
		RequiresConsent: false,
	}

	for _, response := range []string{"y", "yes", "YES"} {
		if IsRepairApproved(action, response) {
			t.Fatalf(
				"action without explicit consent requirement must not be approved by response %q",
				response,
			)
		}
	}
}
