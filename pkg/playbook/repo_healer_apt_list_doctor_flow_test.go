package playbook

import (
	"os"
	"strings"
	"testing"
)

func TestRunSelfHealingTroubleshooterExposesReadOnlyAPTListDoctorMode(
	t *testing.T,
) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		`[4] Run remote APT-list Doctor on a discovered blocked HashiCorp action (read-only)`,
		`Select mode [0-4, default: 1]: `,
		`if modeChoice == "4" {`,
		`runSelectedAPTListDoctorRemoteFlow(client, result)`,
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"RunSelfHealingTroubleshooter must expose APT-list Doctor mode; missing %q",
				required,
			)
		}
	}

	doctorBranch := strings.Index(code, `if modeChoice == "4" {`)
	safeModeBranch := strings.Index(code, `if modeChoice != "2" {`)

	if doctorBranch == -1 || safeModeBranch == -1 {
		t.Fatal("expected both APT-list Doctor and safe-mode branches")
	}
	if doctorBranch > safeModeBranch {
		t.Fatal(
			"APT-list Doctor mode must route before generic non-repair safe-mode return",
		)
	}
}

func TestRunSelectedAPTListDoctorRemoteFlowRemainsReadOnly(t *testing.T) {
	source, err := os.ReadFile("repo_healer_apt_list_doctor_flow.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		"blockedAPTListDoctorActions(result.Actions)",
		"RunSelectedAPTListDoctorRemoteCommand(",
		"Deb822DoctorOutputFormatText",
		"No system changes were made.",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"APT-list Doctor flow missing required read-only behavior %q",
				required,
			)
		}
	}

	for _, forbidden := range []string{
		"runSelectedRepositoryRepairFlow(",
		"inspectSelectedDeb822Repair(",
		"runSelectedDeb822RepairExecutionFlow(",
		"InspectApprovedDeb822Repair(",
		"ReadApprovedDeb822Source(",
		"PreviewDeb822Repair(",
		"ApproveAndApplyDeb822Repair(",
		"ApproveAndApplyAPTRepair(",
		"ApplyDeb822RepairExecution(",
		"ApplyAPTRepair(",
		"CreateAPTFileSnapshot(",
		"AppendRepairAuditEvent(",
		"AppendDeb822RepairAuditEvent(",
		"AppendDeb822RepairPreviewAuditEvent(",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"APT-list Doctor flow must remain read-only; found %q",
				forbidden,
			)
		}
	}
}
