package repohealer

import (
	"strings"
	"testing"
)

func TestFormatRepairActionForEligibleDockerPlan(t *testing.T) {
	actions := BuildRepairPlan(dockerPlanResult())

	if len(actions) != 1 {
		t.Fatalf("expected one Docker repair action, got %d", len(actions))
	}

	output := FormatRepairAction(actions[0])

	for _, expected := range []string{
		"APT Repository Repair Plan",
		"Status: Eligible — explicit approval required",
		"Profile: Docker CE (docker-ce)",
		"Finding: APT_KEYRING_PATH_MISSING",
		"Repository: https://download.docker.com/linux/debian",
		"Distribution: parrot",
		"Codename: lory",
		"Architecture: amd64",
		"Key URL: https://download.docker.com/linux/debian/gpg",
		"9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
		"D3306A018370199E527AE7997EA0A9C3F273FCD8",
		"Keyring: /etc/apt/keyrings/docker.gpg",
		"Source: /etc/apt/sources.list.d/docker.list",
		"deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable",
		"Verification:",
		"apt-get update",
		"Rollback:",
		"Restore only the profile source/keyring files from the pre-repair snapshot.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("formatted eligible Docker plan missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatRepairActionForBlockedDockerPlan(t *testing.T) {
	result := dockerPlanResult()
	result.Target.Codename = "unsupported-release"

	actions := BuildRepairPlan(result)

	if len(actions) != 1 {
		t.Fatalf("expected one blocked Docker action, got %d", len(actions))
	}

	output := FormatRepairAction(actions[0])

	for _, expected := range []string{
		"APT Repository Repair Plan",
		"Status: Blocked — no repair will run",
		"Profile: Docker CE (docker-ce)",
		"Finding: APT_KEYRING_PATH_MISSING",
		"Repository: https://download.docker.com/linux/debian",
		"Reason: Docker Parrot suite review required: unsupported Parrot codename \"unsupported-release\"",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("formatted blocked Docker plan missing %q:\n%s", expected, output)
		}
	}

	for _, unexpected := range []string{
		"Rendered source:",
		"Planned steps:",
		"Verification:",
		"Rollback:",
		"apt-get update",
		"/etc/apt/keyrings/docker.gpg",
	} {
		if strings.Contains(output, unexpected) {
			t.Fatalf("blocked Docker plan must not show %q:\n%s", unexpected, output)
		}
	}
}
