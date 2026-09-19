package playbook

import (
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

func safeBlockedHashiCorpAPTListRepairPlaybookDoctorReport(
	action repohealer.RepairAction,
) repohealer.APTListDoctorReport {
	return repohealer.APTListDoctorReport{
		Overall:             repohealer.APTListDoctorStatusBlocked,
		Target:              action.Target,
		ActionID:            action.ID,
		ProfileID:           action.ProfileID,
		RepositoryURL:       action.RepositoryURL,
		SourceFile:          action.SourceFile,
		SourceLine:          action.SourceLine,
		KeyringPath:         action.KeyringPath,
		ExpectedFingerprint: repohealer.HashiCorpAPTListExpectedFingerprint,
		Checks: []repohealer.APTListDoctorCheck{
			{
				Name:    "remote_source_file",
				Status:  repohealer.APTListDoctorStatusReady,
				Message: "Source list is a safe regular file.",
			},
			{
				Name:    "remote_keyring_file",
				Status:  repohealer.APTListDoctorStatusReady,
				Message: "Keyring is a safe regular file.",
			},
			{
				Name:    "remote_apt_get",
				Status:  repohealer.APTListDoctorStatusReady,
				Message: "apt-get is available.",
			},
			{
				Name:    "remote_gpg",
				Status:  repohealer.APTListDoctorStatusReady,
				Message: "gpg is available.",
			},
			{
				Name:    "expected_signing_key",
				Status:  repohealer.APTListDoctorStatusBlocked,
				Message: "The expected HashiCorp signing fingerprint is absent from the pinned keyring.",
			},
		},
	}
}

func readyHashiCorpAPTListRepairPlaybookPreview(
	t *testing.T,
	action repohealer.RepairAction,
) repohealer.APTListRepairPreview {
	t.Helper()

	preview := repohealer.PreviewBlockedHashiCorpAPTListRepair(
		safeBlockedHashiCorpAPTListRepairPlaybookDoctorReport(action),
	)
	if !preview.Ready {
		t.Fatalf("HashiCorp APT-list preview unexpectedly blocked: %s", preview.Reason)
	}

	return preview
}

func TestPrepareSelectedHashiCorpAPTListRepairBuildsCanonicalRequest(
	t *testing.T,
) {
	action := blockedHashiCorpAPTListPlaybookAction()

	got, err := prepareSelectedHashiCorpAPTListRepair(
		action,
		readyHashiCorpAPTListRepairPlaybookPreview(t, action),
		repohealer.HashiCorpAPTListRepairConfirmation,
	)
	if err != nil {
		t.Fatalf("prepareSelectedHashiCorpAPTListRepair() error = %v", err)
	}

	if got.ActionID != action.ID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, action.ID)
	}
	if got.ProfileID != repohealer.HashiCorpAPTListProfileID {
		t.Fatalf(
			"profile ID = %q, want %q",
			got.ProfileID,
			repohealer.HashiCorpAPTListProfileID,
		)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.KeyringPath != repohealer.HashiCorpAPTListKeyringPath {
		t.Fatalf(
			"keyring path = %q, want %q",
			got.KeyringPath,
			repohealer.HashiCorpAPTListKeyringPath,
		)
	}
	if got.ExpectedFingerprint == "" {
		t.Fatal("expected fingerprint is empty")
	}
}

func TestPrepareSelectedHashiCorpAPTListRepairRejectsUnsafeActionsAndConfirmation(
	t *testing.T,
) {
	base := blockedHashiCorpAPTListPlaybookAction()

	tests := []struct {
		name       string
		mutate     func(*repohealer.RepairAction)
		confirm    string
		wantReason string
	}{
		{
			name:       "Eligible action",
			mutate:     func(action *repohealer.RepairAction) { action.Eligible = true },
			confirm:    repohealer.HashiCorpAPTListRepairConfirmation,
			wantReason: "not an original blocked HashiCorp APT-list action",
		},
		{
			name:       "Consent-bearing action",
			mutate:     func(action *repohealer.RepairAction) { action.RequiresConsent = true },
			confirm:    repohealer.HashiCorpAPTListRepairConfirmation,
			wantReason: "not an original blocked HashiCorp APT-list action",
		},
		{
			name: "Non-APT-list action",
			mutate: func(action *repohealer.RepairAction) {
				action.SourceFormat = repohealer.SourceFormatDeb822
			},
			confirm:    repohealer.HashiCorpAPTListRepairConfirmation,
			wantReason: "not an original blocked HashiCorp APT-list action",
		},
		{
			name:       "Wrong profile",
			mutate:     func(action *repohealer.RepairAction) { action.ProfileID = "docker-ce" },
			confirm:    repohealer.HashiCorpAPTListRepairConfirmation,
			wantReason: "does not resolve to the verified HashiCorp APT profile",
		},
		{
			name:       "Wrong confirmation",
			mutate:     func(*repohealer.RepairAction) {},
			confirm:    "yes",
			wantReason: "exact confirmation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preview := readyHashiCorpAPTListRepairPlaybookPreview(t, base)

			action := base
			test.mutate(&action)

			got, err := prepareSelectedHashiCorpAPTListRepair(
				action,
				preview,
				test.confirm,
			)
			if err == nil {
				t.Fatalf(
					"prepareSelectedHashiCorpAPTListRepair() unexpectedly succeeded: %#v",
					got,
				)
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
		})
	}
}

func TestPrepareSelectedHashiCorpAPTListRepairRejectsMismatchedPreview(
	t *testing.T,
) {
	action := blockedHashiCorpAPTListPlaybookAction()
	preview := readyHashiCorpAPTListRepairPlaybookPreview(t, action)
	preview.ActionID = "other-action"

	_, err := prepareSelectedHashiCorpAPTListRepair(
		action,
		preview,
		repohealer.HashiCorpAPTListRepairConfirmation,
	)
	if err == nil {
		t.Fatal("prepareSelectedHashiCorpAPTListRepair() unexpectedly succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "action") {
		t.Fatalf("error = %q, want action binding failure", err)
	}
}
