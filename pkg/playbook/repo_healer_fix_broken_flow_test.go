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
		`runAPTFixBrokenRepairFlow(client, repoHealerExecutor{client: client})`,
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

// TestRunAPTFixBrokenRepairFlowChecksPolicyBeforeTypedConfirmation confirms the operator
// policy check appears before the "FIX BROKEN PACKAGES" apply prompt in source order, and that
// the real exact-phrase confirmation prompt is still present unweakened.
func TestRunAPTFixBrokenRepairFlowChecksPolicyBeforeTypedConfirmation(t *testing.T) {
	source, err := os.ReadFile("repo_healer_fix_broken_flow.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	policyCheckIndex := strings.Index(code, "printOperatorPolicyGateIfDisabled(")
	applyPromptIndex := strings.Index(code, "Type FIX BROKEN PACKAGES (exact phrase) to apply")

	if policyCheckIndex == -1 {
		t.Fatal("expected a printOperatorPolicyGateIfDisabled call")
	}
	if applyPromptIndex == -1 {
		t.Fatal("expected the exact-phrase apply confirmation prompt to still be present")
	}
	if policyCheckIndex > applyPromptIndex {
		t.Fatal("the operator policy check must appear before the exact-phrase apply prompt")
	}

	if !strings.Contains(code, "repohealer.APTFixBrokenRepairExecutionEnabledEnv") {
		t.Fatal("expected the exact operator-policy env var name to be referenced, not hardcoded")
	}
}
