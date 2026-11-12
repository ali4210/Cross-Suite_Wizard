package playbook

import (
	"os"
	"strings"
	"testing"
)

// TestRunSelectedAPTListRepairExecutionFlowChecksPolicyBeforeTypedYes confirms the operator
// policy check (and its plain-language BLOCKED message naming the exact env var) appears before
// the "type yes to apply" prompt in source order, and that the apply confirmation prompt itself
// is still present unweakened — the policy pre-check only skips asking a question whose answer
// would be rejected anyway, it never bypasses the real approval gate.
func TestRunSelectedAPTListRepairExecutionFlowChecksPolicyBeforeTypedYes(t *testing.T) {
	source, err := os.ReadFile("repo_healer_apt_list_repair_flow.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	policyCheckIndex := strings.Index(code, "printOperatorPolicyGateIfDisabled(")
	applyPromptIndex := strings.Index(code, "Type yes to apply this exact reviewed HashiCorp APT-list repair")

	if policyCheckIndex == -1 {
		t.Fatal("expected a printOperatorPolicyGateIfDisabled call")
	}
	if applyPromptIndex == -1 {
		t.Fatal("expected the typed-yes apply confirmation prompt to still be present")
	}
	if policyCheckIndex > applyPromptIndex {
		t.Fatal("the operator policy check must appear before the typed-yes apply prompt")
	}

	if !strings.Contains(code, "repohealer.HashiCorpAPTListRepairExecutionEnabledEnv") {
		t.Fatal("expected the exact operator-policy env var name to be referenced, not hardcoded")
	}
	if !strings.Contains(code, "repohealer.ApproveAndApplyHashiCorpAPTListRepair(") {
		t.Fatal("the real gated apply call must still be present; the pre-check must not replace it")
	}
}
