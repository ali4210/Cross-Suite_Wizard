package repohealer

import "strings"

func IsRepairApproved(action RepairAction, response string) bool {
	if !action.Eligible || !action.RequiresConsent {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(response)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
