package playbook

import (
	"testing"

	"cross-ssh/pkg/repohealer"
)

func testRepairActions() []repohealer.RepairAction {
	return []repohealer.RepairAction{
		{
			ID:                 "apt-keyring-repair-docker-ce",
			ProfileDisplayName: "Docker CE",
			Eligible:           true,
		},
		{
			ID:                 "apt-source-binding-repair-docker-ce",
			ProfileDisplayName: "Docker CE",
			Eligible:           false,
		},
	}
}

func TestSelectRepositoryRepairActionSelectsOneBasedIndex(t *testing.T) {
	actions := testRepairActions()

	got, ok := selectRepositoryRepairAction(actions, "1")

	if !ok {
		t.Fatal("expected valid selection")
	}
	if got.ID != "apt-keyring-repair-docker-ce" {
		t.Fatalf("selected ID = %q", got.ID)
	}
}

func TestSelectRepositoryRepairActionSelectsBlockedActionForPreview(t *testing.T) {
	actions := testRepairActions()

	got, ok := selectRepositoryRepairAction(actions, "2")

	if !ok {
		t.Fatal("blocked action must still be selectable for preview")
	}
	if got.Eligible {
		t.Fatal("expected blocked action to remain blocked after selection")
	}
}

func TestSelectRepositoryRepairActionRejectsCancelAndInvalidInputs(t *testing.T) {
	actions := testRepairActions()

	for _, input := range []string{
		"",
		" ",
		"0",
		"q",
		"Q",
		"back",
		"-1",
		"3",
		"999",
		"abc",
		"1.5",
	} {
		if _, ok := selectRepositoryRepairAction(actions, input); ok {
			t.Fatalf("input %q must not select an action", input)
		}
	}
}

func TestSelectRepositoryRepairActionRejectsAnyInputForEmptyActions(t *testing.T) {
	if _, ok := selectRepositoryRepairAction(nil, "1"); ok {
		t.Fatal("empty action list must not select an action")
	}
}
