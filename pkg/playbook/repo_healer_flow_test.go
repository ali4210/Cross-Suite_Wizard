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

func TestInspectSelectedDeb822RepairRejectsNonDeb822OrEligibleActions(t *testing.T) {
	base := repohealer.RepairAction{
		ID:              "apt-keyring-repair-docker-ce",
		FindingCode:     "APT_KEYRING_PATH_MISSING",
		ProfileID:       "docker-ce",
		RepositoryURL:   "https://download.docker.com/linux/debian",
		SourceFile:      "/etc/apt/sources.list.d/docker.sources",
		SourceLine:      1,
		SourceFormat:    repohealer.SourceFormatDeb822,
		Eligible:        false,
		RequiresConsent: false,
	}

	result := repohealer.Result{
		Findings: []repohealer.Finding{
			{
				Code:          base.FindingCode,
				RepositoryURL: base.RepositoryURL,
				SourceFile:    base.SourceFile,
				SourceLine:    base.SourceLine,
				SourceFormat:  base.SourceFormat,
			},
		},
	}

	tests := []struct {
		name   string
		mutate func(*repohealer.RepairAction)
	}{
		{
			name: "Eligible action",
			mutate: func(action *repohealer.RepairAction) {
				action.Eligible = true
			},
		},
		{
			name: "Consent-bearing action",
			mutate: func(action *repohealer.RepairAction) {
				action.RequiresConsent = true
			},
		},
		{
			name: "Classic list action",
			mutate: func(action *repohealer.RepairAction) {
				action.SourceFormat = repohealer.SourceFormatAPTList
			},
		},
		{
			name: "Unknown source format",
			mutate: func(action *repohealer.RepairAction) {
				action.SourceFormat = repohealer.SourceFormatUnknown
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := base
			test.mutate(&action)

			_, inspected := inspectSelectedDeb822Repair(
				nil,
				result,
				action,
			)
			if inspected {
				t.Fatal(
					"non-blocked-Deb822 action must not enter inspection flow",
				)
			}
		})
	}
}

func TestInspectSelectedDeb822RepairRejectsUnboundAction(t *testing.T) {
	action := repohealer.RepairAction{
		ID:              "apt-keyring-repair-docker-ce",
		FindingCode:     "APT_KEYRING_PATH_MISSING",
		ProfileID:       "docker-ce",
		RepositoryURL:   "https://download.docker.com/linux/debian",
		SourceFile:      "/etc/apt/sources.list.d/docker.sources",
		SourceLine:      1,
		SourceFormat:    repohealer.SourceFormatDeb822,
		Eligible:        false,
		RequiresConsent: false,
	}

	result := repohealer.Result{
		Findings: []repohealer.Finding{
			{
				Code:          action.FindingCode,
				RepositoryURL: action.RepositoryURL,
				SourceFile:    "/etc/apt/sources.list.d/other.sources",
				SourceLine:    action.SourceLine,
				SourceFormat:  action.SourceFormat,
			},
		},
	}

	_, inspected := inspectSelectedDeb822Repair(
		nil,
		result,
		action,
	)
	if inspected {
		t.Fatal("unbound Deb822 action must not enter inspection flow")
	}
}

func TestInspectSelectedDeb822RepairRejectsUnknownProfile(t *testing.T) {
	action := repohealer.RepairAction{
		ID:              "apt-keyring-repair-unknown",
		FindingCode:     "APT_KEYRING_PATH_MISSING",
		ProfileID:       "unknown",
		RepositoryURL:   "https://unknown.example.invalid/apt",
		SourceFile:      "/etc/apt/sources.list.d/unknown.sources",
		SourceLine:      1,
		SourceFormat:    repohealer.SourceFormatDeb822,
		Eligible:        false,
		RequiresConsent: false,
	}

	result := repohealer.Result{
		Findings: []repohealer.Finding{
			{
				Code:          action.FindingCode,
				RepositoryURL: action.RepositoryURL,
				SourceFile:    action.SourceFile,
				SourceLine:    action.SourceLine,
				SourceFormat:  action.SourceFormat,
			},
		},
	}

	_, inspected := inspectSelectedDeb822Repair(
		nil,
		result,
		action,
	)
	if inspected {
		t.Fatal("unknown vendor profile must not enter inspection flow")
	}
}
