package playbook

import (
	"os"
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

func blockedHashiCorpAPTListPlaybookAction() repohealer.RepairAction {
	return repohealer.RepairAction{
		ID:              "apt-keyring-repair-hashicorp",
		FindingCode:     "APT_REPO_KEY_MISSING",
		ProfileID:       repohealer.HashiCorpAPTListProfileID,
		RepositoryURL:   repohealer.HashiCorpAPTListRepositoryURL,
		SourceFile:      "/etc/apt/sources.list.d/hashicorp.list",
		SourceLine:      1,
		SourceFormat:    repohealer.SourceFormatAPTList,
		KeyringPath:     repohealer.HashiCorpAPTListKeyringPath,
		Eligible:        false,
		RequiresConsent: false,
		Target: repohealer.TargetFacts{
			Platform:       repohealer.PlatformLinux,
			Distribution:   "debian",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: repohealer.ManagerAPT,
		},
	}
}

func TestRunSelectedAPTListDoctorRemoteCommandRejectsUnknownFormatBeforeRemoteProbe(
	t *testing.T,
) {
	action := blockedHashiCorpAPTListPlaybookAction()

	got, err := RunSelectedAPTListDoctorRemoteCommand(
		nil,
		action.Target,
		action,
		Deb822DoctorOutputFormat("yaml"),
	)
	if err == nil {
		t.Fatalf(
			"RunSelectedAPTListDoctorRemoteCommand() unexpectedly succeeded: %#v",
			got,
		)
	}
	if got.ExitCode != repohealer.APTListDoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.APTListDoctorExitUnknown,
		)
	}
	if got.Output != "" {
		t.Fatalf("output = %q, want empty", got.Output)
	}
	if !strings.Contains(err.Error(), "unsupported APT list Doctor output format") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestRunSelectedAPTListDoctorRemoteCommandRejectsNilClientBeforeRemoteProbe(
	t *testing.T,
) {
	action := blockedHashiCorpAPTListPlaybookAction()

	got, err := RunSelectedAPTListDoctorRemoteCommand(
		nil,
		action.Target,
		action,
		Deb822DoctorOutputFormatText,
	)
	if err == nil {
		t.Fatalf(
			"RunSelectedAPTListDoctorRemoteCommand() unexpectedly succeeded: %#v",
			got,
		)
	}
	if got.ExitCode != repohealer.APTListDoctorExitUnknown {
		t.Fatalf(
			"exit code = %d, want %d",
			got.ExitCode,
			repohealer.APTListDoctorExitUnknown,
		)
	}
	if got.Output != "" {
		t.Fatalf("output = %q, want empty", got.Output)
	}
	if !strings.Contains(err.Error(), "remote client is nil") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestRunSelectedAPTListDoctorRemoteCommandUsesReadOnlyRemoteDoctorService(
	t *testing.T,
) {
	source, err := os.ReadFile("repo_healer_apt_list_doctor_adapter.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	if !strings.Contains(
		code,
		"repohealer.RunSelectedAPTListDoctorRemoteService(",
	) {
		t.Fatal(
			"APT list Doctor adapter must delegate to the APT list Doctor service",
		)
	}

	for _, forbidden := range []string{
		"InspectApprovedDeb822Repair(",
		"ReadApprovedDeb822Source(",
		"PreviewDeb822Repair(",
		"ApproveAndApplyDeb822Repair(",
		"ApproveAndApplyAPTRepair(",
		"ApplyDeb822RepairExecution(",
		"CreateAPTFileSnapshot(",
		"AppendDeb822RepairAuditEvent(",
		"AppendDeb822RepairPreviewAuditEvent(",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"APT list Doctor adapter must remain read-only; found %q",
				forbidden,
			)
		}
	}
}

func TestAPTListDoctorAdapterSourceRemainsReadOnly(t *testing.T) {
	source, err := os.ReadFile("repo_healer_apt_list_doctor_adapter.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		"repohealer.RunSelectedAPTListDoctorRemoteService(",
		"repohealer.FormatAPTListDoctorReport(",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"APT list Doctor adapter source missing required call %q",
				required,
			)
		}
	}

	for _, forbidden := range []string{
		"ProbeSelectedAPTListRepairMetadata(",
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
		"apt-get update",
		"apt-get install",
		"curl ",
		"wget ",
		"gpg --dearmor",
		"gpg --import",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"APT list Doctor adapter must remain read-only; found %q",
				forbidden,
			)
		}
	}
}
