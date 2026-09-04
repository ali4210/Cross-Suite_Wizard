package repohealer

import (
	"strings"
	"testing"
)

func dockerPlanResult() Result {
	return Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		Findings: []Finding{
			{
				Code:          "APT_KEYRING_PATH_MISSING",
				RepositoryURL: "https://download.docker.com/linux/debian",
			},
		},
	}
}

func TestBuildRepairPlanForMicrosoftVSCode(t *testing.T) {
	result := Result{
		Target: TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
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

	action := actions[0]
	if action.ID != "apt-keyring-repair-microsoft-vscode" {
		t.Fatalf("action ID = %q", action.ID)
	}
	if !action.Eligible {
		t.Fatalf("Microsoft plan must be eligible, block reason: %s", action.BlockReason)
	}
	if !action.RequiresConsent {
		t.Fatal("Microsoft repair plan must require explicit consent")
	}
	if action.RenderedSource == "" {
		t.Fatal("Microsoft repair plan must include a rendered source line")
	}
}

func TestBuildRepairPlanForDocker(t *testing.T) {
	actions := BuildRepairPlan(dockerPlanResult())

	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}

	action := actions[0]
	if action.ID != "apt-keyring-repair-docker-ce" {
		t.Fatalf("action ID = %q", action.ID)
	}
	if !action.Eligible {
		t.Fatalf("Docker plan must be eligible, block reason: %s", action.BlockReason)
	}
	if !action.RequiresConsent {
		t.Fatal("Docker repair plan must require explicit consent")
	}
	if action.ProfileID != "docker-ce" {
		t.Fatalf("profile ID = %q, want docker-ce", action.ProfileID)
	}
	if action.KeyURL != "https://download.docker.com/linux/debian/gpg" {
		t.Fatalf("key URL = %q", action.KeyURL)
	}
	if action.KeyringPath != "/etc/apt/keyrings/docker.gpg" {
		t.Fatalf("keyring path = %q", action.KeyringPath)
	}
	if action.SourceFile != "/etc/apt/sources.list.d/docker.list" {
		t.Fatalf("source file = %q", action.SourceFile)
	}
	if action.RenderedSource != "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" {
		t.Fatalf("rendered source = %q", action.RenderedSource)
	}
	if len(action.ExpectedFingerprints) != 2 {
		t.Fatalf("expected 2 Docker fingerprints, got %d", len(action.ExpectedFingerprints))
	}
	if !strings.Contains(strings.Join(action.Commands, "\n"), action.RenderedSource) {
		t.Fatalf("Docker plan commands must show rendered source:\n%s", strings.Join(action.Commands, "\n"))
	}
}

func TestBuildRepairPlanBlocksUnsupportedDockerSuite(t *testing.T) {
	result := dockerPlanResult()
	result.Target.Codename = "unsupported-release"

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected 1 blocked action, got %d", len(actions))
	}

	action := actions[0]
	if action.Eligible {
		t.Fatal("unsupported Docker suite must be blocked")
	}
	if action.Risk != RiskBlocked {
		t.Fatalf("risk = %q, want %q", action.Risk, RiskBlocked)
	}
	if action.RequiresConsent {
		t.Fatal("blocked plan must not request repair consent")
	}
	if action.BlockReason == "" {
		t.Fatal("blocked plan must include a reason")
	}
	if action.RenderedSource != "" {
		t.Fatalf("blocked plan must not expose a rendered source, got %q", action.RenderedSource)
	}
	if len(action.Commands) != 0 {
		t.Fatalf("blocked plan must not contain mutation commands, got %d", len(action.Commands))
	}
}

func TestBuildRepairPlanDeduplicatesProfiles(t *testing.T) {
	result := dockerPlanResult()
	result.Findings = append(result.Findings, Finding{
		Code:          "APT_KEYRING_PATH_MISSING",
		RepositoryURL: "https://download.docker.com/linux/debian",
	})

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected a single Docker action, got %d", len(actions))
	}
}

func TestBuildRepairPlanRejectsUnknownRepository(t *testing.T) {
	result := dockerPlanResult()
	result.Findings[0].RepositoryURL = "https://unknown.example.invalid/apt"

	actions := BuildRepairPlan(result)

	if len(actions) != 0 {
		t.Fatalf("unknown repository must not receive a repair action, got %d", len(actions))
	}
}

func TestBuildRepairPlanForDockerKeyringBindingMismatch(t *testing.T) {
	result := dockerPlanResult()
	result.Findings[0].Code = "APT_SOURCE_KEYRING_MISMATCH"

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected one Docker binding-mismatch action, got %d", len(actions))
	}

	action := actions[0]
	if action.ID != "apt-source-binding-repair-docker-ce" {
		t.Fatalf("action ID = %q", action.ID)
	}
	if action.FindingCode != "APT_SOURCE_KEYRING_MISMATCH" {
		t.Fatalf("finding code = %q", action.FindingCode)
	}
	if !action.Eligible {
		t.Fatalf("Docker binding mismatch must be eligible, block reason: %s", action.BlockReason)
	}
	if !action.RequiresConsent {
		t.Fatal("Docker binding mismatch must require explicit consent")
	}
}
