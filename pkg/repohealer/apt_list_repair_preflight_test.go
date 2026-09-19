package repohealer

import (
	"reflect"
	"strings"
	"testing"
)

func readyHashiCorpAPTListRepairExecutionRequest(
	t *testing.T,
) HashiCorpAPTListRepairExecutionRequest {
	t.Helper()

	request, err := BuildHashiCorpAPTListRepairExecutionRequest(
		readyHashiCorpAPTListRepairPreview(t),
		HashiCorpAPTListRepairConfirmation,
	)
	if err != nil {
		t.Fatalf("BuildHashiCorpAPTListRepairExecutionRequest() error = %v", err)
	}

	return request
}

func readyHashiCorpAPTListRepairPreflightProbe() HashiCorpAPTListRepairPreflightProbe {
	return HashiCorpAPTListRepairPreflightProbe{
		Source: HashiCorpAPTListRepairPreflightFile{
			State:  HashiCorpAPTListRepairPreflightFilePresent,
			UID:    0,
			Mode:   "644",
			Size:   126,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Keyring: HashiCorpAPTListRepairPreflightFile{
			State:  HashiCorpAPTListRepairPreflightFilePresent,
			UID:    0,
			Mode:   "644",
			Size:   1213,
			SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		APTAvailable:     true,
		GPGAvailable:     true,
		InstallAvailable: true,
		MVAvailable:      true,
		SHA256Available:  true,
		APTLockActive:    false,
	}
}

func blockedHashiCorpAPTListRepairDoctorReport(
	t *testing.T,
) APTListDoctorReport {
	t.Helper()

	report := safeBlockedHashiCorpAPTListDoctorReport()
	if err := ValidateAPTListDoctorReport(report); err != nil {
		t.Fatalf("ValidateAPTListDoctorReport() error = %v", err)
	}

	return report
}

func TestEvaluateHashiCorpAPTListRepairPreflightAcceptsBoundSafeState(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	report := blockedHashiCorpAPTListRepairDoctorReport(t)

	got := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		report,
	)

	if !got.Ready {
		t.Fatalf("preflight unexpectedly blocked: %s", got.Reason)
	}
	if !reflect.DeepEqual(got.Request, request) {
		t.Fatalf("request = %#v, want %#v", got.Request, request)
	}
	if got.Source.SHA256 != probe.Source.SHA256 {
		t.Fatalf("source SHA-256 = %q", got.Source.SHA256)
	}
	if got.Keyring.SHA256 != probe.Keyring.SHA256 {
		t.Fatalf("keyring SHA-256 = %q", got.Keyring.SHA256)
	}
	if !reflect.DeepEqual(got.DoctorReport, report) {
		t.Fatalf("Doctor report = %#v, want %#v", got.DoctorReport, report)
	}
}

func TestEvaluateHashiCorpAPTListRepairPreflightRejectsUnsafeState(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(
			*HashiCorpAPTListRepairExecutionRequest,
			*HashiCorpAPTListRepairPreflightProbe,
			*APTListDoctorReport,
		)
		want string
	}{
		{
			name: "Wrong request profile",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				request.ProfileID = "docker-ce"
			},
			want: "profile",
		},
		{
			name: "Source symlink",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.Source.State = HashiCorpAPTListRepairPreflightFileSymlink
			},
			want: "source",
		},
		{
			name: "Keyring unsafe owner",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.Keyring.State = HashiCorpAPTListRepairPreflightFileUnsafeOwner
			},
			want: "keyring",
		},
		{
			name: "Source unsafe mode",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.Source.State = HashiCorpAPTListRepairPreflightFileUnsafeMode
			},
			want: "source",
		},
		{
			name: "Empty source hash",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.Source.SHA256 = ""
			},
			want: "source",
		},
		{
			name: "Malformed keyring hash",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.Keyring.SHA256 = "not-a-sha256"
			},
			want: "keyring",
		},
		{
			name: "Missing gpg",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.GPGAvailable = false
			},
			want: "gpg",
		},
		{
			name: "Missing install",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.InstallAvailable = false
			},
			want: "install",
		},
		{
			name: "Missing apt-get",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.APTAvailable = false
			},
			want: "apt-get",
		},
		{
			name: "Missing mv",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.MVAvailable = false
			},
			want: "mv",
		},
		{
			name: "Missing sha256sum",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.SHA256Available = false
			},
			want: "sha256sum",
		},
		{
			name: "Active APT lock",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				probe.APTLockActive = true
			},
			want: "lock",
		},
		{
			name: "Doctor becomes ready",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				report.Overall = APTListDoctorStatusReady
			},
			want: "Doctor",
		},
		{
			name: "Doctor expected key check becomes ready",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				for index := range report.Checks {
					if report.Checks[index].Name == "expected_signing_key" {
						report.Checks[index].Status = APTListDoctorStatusReady
						return
					}
				}

				t.Fatal("expected_signing_key check not found")
			},
			want: "expected_signing_key",
		},
		{
			name: "Doctor request binding changes",
			mutate: func(
				request *HashiCorpAPTListRepairExecutionRequest,
				probe *HashiCorpAPTListRepairPreflightProbe,
				report *APTListDoctorReport,
			) {
				report.KeyringPath = "/tmp/other.gpg"
			},
			want: "keyring",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readyHashiCorpAPTListRepairExecutionRequest(t)
			probe := readyHashiCorpAPTListRepairPreflightProbe()
			report := blockedHashiCorpAPTListRepairDoctorReport(t)
			test.mutate(&request, &probe, &report)

			got := EvaluateHashiCorpAPTListRepairPreflight(
				request,
				probe,
				report,
			)

			if got.Ready {
				t.Fatalf("unsafe preflight unexpectedly ready: %#v", got)
			}
			if !strings.Contains(
				strings.ToLower(got.Reason),
				strings.ToLower(test.want),
			) {
				t.Fatalf(
					"reason = %q, want it to contain %q",
					got.Reason,
					test.want,
				)
			}
		})
	}
}

func TestEvaluateHashiCorpAPTListRepairPreflightAllowsMissingKeyring(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	probe.Keyring = HashiCorpAPTListRepairPreflightFile{
		State: HashiCorpAPTListRepairPreflightFileMissing,
	}
	report := blockedHashiCorpAPTListRepairDoctorReport(t)
	setHashiCorpAPTListDoctorCheckStatus(
		t,
		&report,
		"remote_keyring_file",
		APTListDoctorStatusBlocked,
	)

	got := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		report,
	)

	if !got.Ready {
		t.Fatalf(
			"preflight unexpectedly blocked for a missing keyring: %s",
			got.Reason,
		)
	}

	if got.Keyring.State != HashiCorpAPTListRepairPreflightFileMissing {
		t.Fatalf(
			"keyring state = %q, want %q",
			got.Keyring.State,
			HashiCorpAPTListRepairPreflightFileMissing,
		)
	}
}

func TestEvaluateHashiCorpAPTListRepairPreflightAllowsMissingKeyringWithNoFileMetadata(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	probe.Keyring = HashiCorpAPTListRepairPreflightFile{
		State:  HashiCorpAPTListRepairPreflightFileMissing,
		UID:    1000,
		Mode:   "777",
		Size:   -1,
		SHA256: "not-a-sha256",
	}
	report := blockedHashiCorpAPTListRepairDoctorReport(t)
	setHashiCorpAPTListDoctorCheckStatus(
		t,
		&report,
		"remote_keyring_file",
		APTListDoctorStatusBlocked,
	)

	got := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		report,
	)

	if !got.Ready {
		t.Fatalf(
			"preflight unexpectedly blocked for a missing keyring: %s",
			got.Reason,
		)
	}
}

func TestEvaluateHashiCorpAPTListRepairPreflightRejectsSymlinkKeyring(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	probe.Keyring.State = HashiCorpAPTListRepairPreflightFileSymlink
	report := blockedHashiCorpAPTListRepairDoctorReport(t)

	got := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		report,
	)

	if got.Ready {
		t.Fatalf("preflight unexpectedly ready for a symlink keyring")
	}
	if !strings.Contains(strings.ToLower(got.Reason), "keyring") {
		t.Fatalf("reason = %q, want it to contain keyring", got.Reason)
	}
}

func setHashiCorpAPTListDoctorCheckStatus(
	t *testing.T,
	report *APTListDoctorReport,
	name string,
	status APTListDoctorStatus,
) {
	t.Helper()

	for index := range report.Checks {
		if report.Checks[index].Name == name {
			report.Checks[index].Status = status
			return
		}
	}

	t.Fatalf("Doctor check %q not found", name)
}

func TestEvaluateHashiCorpAPTListRepairPreflightAllowsMissingKeyringWithBlockedDoctorCheck(
	t *testing.T,
) {
	request := readyHashiCorpAPTListRepairExecutionRequest(t)
	probe := readyHashiCorpAPTListRepairPreflightProbe()
	probe.Keyring = HashiCorpAPTListRepairPreflightFile{
		State: HashiCorpAPTListRepairPreflightFileMissing,
	}
	report := blockedHashiCorpAPTListRepairDoctorReport(t)
	setHashiCorpAPTListDoctorCheckStatus(
		t,
		&report,
		"remote_keyring_file",
		APTListDoctorStatusBlocked,
	)

	got := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		probe,
		report,
	)

	if !got.Ready {
		t.Fatalf(
			"preflight unexpectedly blocked for missing keyring with blocked Doctor check: %s",
			got.Reason,
		)
	}
}

func TestEvaluateHashiCorpAPTListRepairPreflightRejectsConflictingDoctorKeyringState(
	t *testing.T,
) {
	tests := []struct {
		name         string
		keyringState HashiCorpAPTListRepairPreflightFileState
		doctorState  APTListDoctorStatus
	}{
		{
			name:         "Missing keyring with Doctor ready",
			keyringState: HashiCorpAPTListRepairPreflightFileMissing,
			doctorState:  APTListDoctorStatusReady,
		},
		{
			name:         "Present keyring with Doctor blocked",
			keyringState: HashiCorpAPTListRepairPreflightFilePresent,
			doctorState:  APTListDoctorStatusBlocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readyHashiCorpAPTListRepairExecutionRequest(t)
			probe := readyHashiCorpAPTListRepairPreflightProbe()
			if test.keyringState == HashiCorpAPTListRepairPreflightFileMissing {
				probe.Keyring = HashiCorpAPTListRepairPreflightFile{
					State: HashiCorpAPTListRepairPreflightFileMissing,
				}
			} else {
				probe.Keyring.State = test.keyringState
			}

			report := blockedHashiCorpAPTListRepairDoctorReport(t)
			setHashiCorpAPTListDoctorCheckStatus(
				t,
				&report,
				"remote_keyring_file",
				test.doctorState,
			)

			got := EvaluateHashiCorpAPTListRepairPreflight(
				request,
				probe,
				report,
			)

			if got.Ready {
				t.Fatalf(
					"preflight unexpectedly ready for keyring state %q and Doctor status %q",
					test.keyringState,
					test.doctorState,
				)
			}
			if !strings.Contains(
				strings.ToLower(got.Reason),
				"keyring",
			) {
				t.Fatalf(
					"reason = %q, want it to contain keyring",
					got.Reason,
				)
			}
		})
	}
}
