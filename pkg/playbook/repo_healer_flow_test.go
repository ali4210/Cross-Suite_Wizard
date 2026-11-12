package playbook

import (
	"os"
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

func TestShouldContinueGatedRepairAfterPreviewAcceptsAYOrYes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "Empty exits after preview", input: "", want: false},
		{name: "Whitespace-only exits after preview", input: " ", want: false},
		{name: "Preview-command exits after preview", input: "p", want: false},
		{name: "Cancel exits after preview", input: "q", want: false},
		{name: "No exits after preview", input: "no", want: false},
		{name: "Long apply does not bypass exact mode", input: "apply", want: false},
		{name: "Exact a continues", input: "a", want: true},
		{name: "Uppercase A continues", input: "A", want: true},
		{name: "Trimmed a continues", input: "  a  ", want: true},
		{name: "y continues", input: "y", want: true},
		{name: "Uppercase Y continues", input: "Y", want: true},
		{name: "yes continues, never a silent exit", input: "yes", want: true},
		{name: "Mixed-case YES continues", input: "YES", want: true},
		{name: "Trimmed yes continues", input: "  yes  ", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldContinueGatedRepairAfterPreview(test.input); got != test.want {
				t.Fatalf(
					"shouldContinueGatedRepairAfterPreview(%q) = %t, want %t",
					test.input,
					got,
					test.want,
				)
			}
		})
	}
}

func TestPrintOperatorPolicyGateIfDisabledReturnsEnabledUnchanged(t *testing.T) {
	if !printOperatorPolicyGateIfDisabled("CROSS_SUITE_EXAMPLE_ENABLED", true) {
		t.Fatal("an enabled policy must allow the caller to proceed")
	}
	if printOperatorPolicyGateIfDisabled("CROSS_SUITE_EXAMPLE_ENABLED", false) {
		t.Fatal("a disabled policy must block the caller from proceeding")
	}
}

// TestRunSelectedDeb822RepairExecutionFlowChecksPolicyBeforeTypedYes mirrors the equivalent
// APT-list and fix-broken tests: the operator policy check (naming the exact env var) must
// appear before the typed-yes apply prompt in source order, and the real apply call must still
// be present unweakened.
func TestRunSelectedDeb822RepairExecutionFlowChecksPolicyBeforeTypedYes(t *testing.T) {
	source, err := os.ReadFile("repo_healer_flow.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	policyCheckIndex := strings.Index(code, "printOperatorPolicyGateIfDisabled(")
	applyPromptIndex := strings.Index(code, "Type yes to apply this exact reviewed Deb822 repair")

	if policyCheckIndex == -1 {
		t.Fatal("expected a printOperatorPolicyGateIfDisabled call")
	}
	if applyPromptIndex == -1 {
		t.Fatal("expected the typed-yes apply confirmation prompt to still be present")
	}
	if policyCheckIndex > applyPromptIndex {
		t.Fatal("the operator policy check must appear before the typed-yes apply prompt")
	}

	if !strings.Contains(code, "repohealer.Deb822RepairExecutionEnabledEnv") {
		t.Fatal("expected the exact operator-policy env var name to be referenced, not hardcoded")
	}
	if !strings.Contains(code, "sudo %s=true") {
		t.Fatal("expected a sudo-safe example command for enabling the policy")
	}
	if !strings.Contains(code, "repohealer.ApproveAndApplyDeb822Repair(") {
		t.Fatal("the real gated apply call must still be present; the pre-check must not replace it")
	}
}

func TestShouldRouteThroughAPTListRepairFlow(t *testing.T) {
	tests := []struct {
		name   string
		format repohealer.SourceFormat
		want   bool
	}{
		{name: "APT-list routes to the APT-list flow", format: repohealer.SourceFormatAPTList, want: true},
		{name: "Deb822 does not route to the APT-list flow", format: repohealer.SourceFormatDeb822, want: false},
		{name: "Unknown format does not route to the APT-list flow", format: repohealer.SourceFormatUnknown, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := repohealer.RepairAction{SourceFormat: test.format}
			if got := shouldRouteThroughAPTListRepairFlow(action); got != test.want {
				t.Fatalf("shouldRouteThroughAPTListRepairFlow(%q) = %t, want %t", test.format, got, test.want)
			}
		})
	}
}

func TestBlockedRepositoryRepairActionStatusLabelNamesThePath(t *testing.T) {
	tests := []struct {
		name     string
		format   repohealer.SourceFormat
		contains string
	}{
		{name: "APT-list", format: repohealer.SourceFormatAPTList, contains: "APT-list"},
		{name: "Deb822", format: repohealer.SourceFormatDeb822, contains: "Deb822"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := repohealer.RepairAction{SourceFormat: test.format}
			got := blockedRepositoryRepairActionStatusLabel(action)
			if !strings.Contains(got, test.contains) {
				t.Fatalf("status label %q does not name the %s path", got, test.contains)
			}
		})
	}
}

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
