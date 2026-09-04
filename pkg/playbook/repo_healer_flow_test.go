package playbook

import (
	"testing"

	"cross-ssh/pkg/repohealer"
)

func TestSelectedRepositoryRepairFlowPolicyBoundaries(t *testing.T) {
	actions := []repohealer.RepairAction{
		{
			ID:              "apt-keyring-repair-docker-ce",
			Eligible:        true,
			RequiresConsent: true,
		},
		{
			ID:              "apt-source-binding-repair-docker-ce",
			Eligible:        false,
			RequiresConsent: false,
			BlockReason:     "unsupported target",
		},
	}

	eligible, ok := selectRepositoryRepairAction(actions, "1")
	if !ok {
		t.Fatal("eligible action must be selectable")
	}
	if !repohealer.IsRepairApproved(eligible, "yes") {
		t.Fatal("eligible selected action must require and accept explicit yes")
	}

	blocked, ok := selectRepositoryRepairAction(actions, "2")
	if !ok {
		t.Fatal("blocked action must be selectable for preview")
	}
	if repohealer.IsRepairApproved(blocked, "yes") {
		t.Fatal("blocked action must never be approved")
	}

	if _, ok := selectRepositoryRepairAction(actions, "0"); ok {
		t.Fatal("cancel must not select an action")
	}
}
