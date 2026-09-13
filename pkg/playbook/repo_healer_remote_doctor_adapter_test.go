package playbook

import (
	"os"
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

func TestRunSelectedDeb822DoctorRemoteCommandRejectsUnknownFormatBeforeRemoteProbe(
	t *testing.T,
) {
	action := blockedDockerDeb822PlaybookAction()

	got, err := RunSelectedDeb822DoctorRemoteCommand(
		nil,
		action.Target,
		action,
		Deb822DoctorOutputFormat("yaml"),
	)
	if err == nil {
		t.Fatalf(
			"RunSelectedDeb822DoctorRemoteCommand() unexpectedly succeeded: %#v",
			got,
		)
	}
	if got.ExitCode != repohealer.Deb822DoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.Deb822DoctorExitUnknown,
		)
	}
	if got.Output != "" {
		t.Fatalf("output = %q, want empty", got.Output)
	}
	if !strings.Contains(err.Error(), "unsupported Deb822 Doctor output format") {
		t.Fatalf("error = %q, want unsupported-format error", err)
	}
}

func TestRunSelectedDeb822DoctorRemoteCommandRejectsNilClientBeforeRemoteProbe(
	t *testing.T,
) {
	action := blockedDockerDeb822PlaybookAction()

	got, err := RunSelectedDeb822DoctorRemoteCommand(
		nil,
		action.Target,
		action,
		Deb822DoctorOutputFormatText,
	)
	if err == nil {
		t.Fatalf(
			"RunSelectedDeb822DoctorRemoteCommand() unexpectedly succeeded: %#v",
			got,
		)
	}
	if got.ExitCode != repohealer.Deb822DoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.Deb822DoctorExitUnknown,
		)
	}
	if got.Output != "" {
		t.Fatalf("output = %q, want empty", got.Output)
	}
	if !strings.Contains(err.Error(), "remote client is nil") {
		t.Fatalf("error = %q, want nil-client error", err)
	}
}

func TestRunSelectedDeb822DoctorRemoteCommandUsesReadOnlyRemoteDoctorService(
	t *testing.T,
) {
	source, err := os.ReadFile("repo_healer_remote_doctor_adapter.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	if !strings.Contains(
		code,
		"repohealer.RunSelectedDeb822DoctorRemoteService(",
	) {
		t.Fatal(
			"remote Doctor adapter must delegate to the remote Deb822 Doctor service",
		)
	}

	for _, forbidden := range []string{
		"InspectApprovedDeb822Repair(",
		"ReadApprovedDeb822Source(",
		"PreviewDeb822Repair(",
		"ApproveAndApplyDeb822Repair(",
		"ApplyDeb822RepairExecution(",
		"CreateAPTFileSnapshot(",
		"AppendDeb822RepairAuditEvent(",
		"AppendDeb822RepairPreviewAuditEvent(",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"remote Doctor adapter must remain read-only; found %q",
				forbidden,
			)
		}
	}
}

func TestRunSelectedDeb822DoctorRemoteFlowRemainsReadOnly(t *testing.T) {
	source, err := os.ReadFile("repo_healer_remote_doctor_adapter.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	if !strings.Contains(
		code,
		"RunSelectedDeb822DoctorRemoteCommand(",
	) {
		t.Fatal(
			"remote Doctor menu flow must call the remote Doctor command adapter",
		)
	}

	for _, forbidden := range []string{
		"runSelectedRepositoryRepairFlow(",
		"inspectSelectedDeb822Repair(",
		"runSelectedDeb822RepairExecutionFlow(",
		"InspectApprovedDeb822Repair(",
		"PreviewDeb822Repair(",
		"ApproveAndApplyDeb822Repair(",
		"ApproveAndApplyAPTRepair(",
		"CreateAPTFileSnapshot(",
		"AppendDeb822RepairAuditEvent(",
		"AppendDeb822RepairPreviewAuditEvent(",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"remote Doctor menu flow must remain read-only; found %q",
				forbidden,
			)
		}
	}
}

func TestRunSelfHealingTroubleshooterExposesReadOnlyRemoteDoctorMode(
	t *testing.T,
) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		`[3] Run remote Deb822 Doctor on a discovered blocked action (read-only)`,
		`Select mode [0-4, default: 1]: `,
		`if modeChoice == "3" {`,
		`runSelectedDeb822DoctorRemoteFlow(client, result)`,
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"RunSelfHealingTroubleshooter must expose remote Doctor mode; missing %q",
				required,
			)
		}
	}

	doctorBranch := strings.Index(
		code,
		`if modeChoice == "3" {`,
	)
	safeModeBranch := strings.Index(
		code,
		`if modeChoice != "2" {`,
	)

	if doctorBranch == -1 || safeModeBranch == -1 {
		t.Fatal("expected both Doctor and safe-mode branches")
	}
	if doctorBranch > safeModeBranch {
		t.Fatal(
			"remote Doctor mode must route before the generic non-repair safe-mode return",
		)
	}
}
