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
