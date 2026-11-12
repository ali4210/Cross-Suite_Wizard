package playbook

import (
	"os"
	"strings"
	"testing"
)

func TestRunSelfHealingTroubleshooterExposesGatedFixBrokenMode(t *testing.T) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		`[5] Review and optionally apply a gated 'apt --fix-broken install' repair`,
		`Select mode [0-5, default: 1]: `,
		`if modeChoice == "5" {`,
		`runAPTFixBrokenRepairFlow(repoHealerExecutor{client: client})`,
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"RunSelfHealingTroubleshooter must expose the gated fix-broken-install mode; missing %q",
				required,
			)
		}
	}
}

func TestRunAPTFixBrokenRepairFlowNeverBypassesConfirmation(t *testing.T) {
	source, err := os.ReadFile("repo_healer_fix_broken_flow.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		"repohealer.BuildAPTFixBrokenPreview(",
		"repohealer.ApproveAndApplyAPTFixBrokenRepair(",
		"FIX BROKEN PACKAGES",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf("fix-broken flow missing required behavior %q", required)
		}
	}

	if strings.Contains(code, `response, "yes"`) || strings.Contains(code, `== "yes"`) {
		t.Fatal("fix-broken flow must require the exact confirmation phrase, not a bare \"yes\" comparison")
	}
	if strings.Contains(code, "apt-mark unhold") {
		t.Fatal("fix-broken flow must never run apt-mark unhold")
	}
}
