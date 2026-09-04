package repohealer

import "testing"

func TestBuildRepairPlanForMicrosoftVSCode(t *testing.T) {
	result := Result{
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://packages.microsoft.com/repos/code",
			},
		},
	}

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].ID != "apt-keyring-repair-microsoft-vscode" {
		t.Fatalf("action ID = %q", actions[0].ID)
	}
}

func TestBuildRepairPlanForDocker(t *testing.T) {
	result := Result{
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://download.docker.com/linux/debian",
			},
		},
	}

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].ID != "apt-keyring-repair-docker-ce" {
		t.Fatalf("action ID = %q", actions[0].ID)
	}
	if !actions[0].RequiresConsent {
		t.Fatal("Docker repair plan must require explicit consent")
	}
}

func TestBuildRepairPlanDeduplicatesProfiles(t *testing.T) {
	result := Result{
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://download.docker.com/linux/debian",
			},
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://download.docker.com/linux/debian",
			},
		},
	}

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected a single Docker action, got %d", len(actions))
	}
}

func TestBuildRepairPlanRejectsUnknownRepository(t *testing.T) {
	result := Result{
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://unknown.example.invalid/apt",
			},
		},
	}

	actions := BuildRepairPlan(result)

	if len(actions) != 0 {
		t.Fatalf("unknown repository must not receive a repair action, got %d", len(actions))
	}
}
