package repohealer

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func aptListDoctorProbeOutput(
	aptGet string,
	gpg string,
	sourceState string,
	sourceMode string,
	sourceSize string,
	keyringState string,
	keyringMode string,
	keyringSize string,
	fingerprints ...string,
) string {
	lines := []string{
		aptListDoctorProbeBegin,
		"apt_get|" + aptGet,
		"gpg|" + gpg,
		"file|source|" + sourceState + "|" + sourceMode + "|" + sourceSize,
		"file|keyring|" + keyringState + "|" + keyringMode + "|" + keyringSize,
	}
	for _, fingerprint := range fingerprints {
		lines = append(lines, "fpr|"+fingerprint)
	}
	lines = append(lines, aptListDoctorProbeEnd)

	return strings.Join(lines, "\n")
}

func aptListDoctorProbeAction() RepairAction {
	return RepairAction{
		ID:              "apt-keyring-repair-hashicorp",
		FindingCode:     "APT_REPO_KEY_MISSING",
		ProfileID:       HashiCorpAPTListProfileID,
		RepositoryURL:   HashiCorpAPTListRepositoryURL,
		SourceFile:      "/etc/apt/sources.list.d/hashicorp.list",
		SourceLine:      1,
		SourceFormat:    SourceFormatAPTList,
		KeyringPath:     HashiCorpAPTListKeyringPath,
		Eligible:        false,
		RequiresConsent: false,
	}
}

func TestProbeSelectedAPTListRepairMetadataReturnsReadOnlyMetadata(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"120",
				"present",
				"644",
				"240",
				HashiCorpAPTListExpectedFingerprint,
			),
		},
	}

	got, err := ProbeSelectedAPTListRepairMetadata(
		exec,
		aptListDoctorProbeAction(),
	)
	if err != nil {
		t.Fatalf("ProbeSelectedAPTListRepairMetadata() error = %v", err)
	}

	if !got.APTAvailable || !got.GPGAvailable {
		t.Fatalf("probe availability = %#v", got)
	}
	if got.Source.State != APTListDoctorFileStatePresent ||
		got.Source.Mode != "644" ||
		got.Source.Size != 120 {
		t.Fatalf("source metadata = %#v", got.Source)
	}
	if got.Keyring.State != APTListDoctorFileStatePresent ||
		got.Keyring.Mode != "644" ||
		got.Keyring.Size != 240 {
		t.Fatalf("keyring metadata = %#v", got.Keyring)
	}
	if len(got.KeyringFingerprints) != 1 ||
		got.KeyringFingerprints[0] != HashiCorpAPTListExpectedFingerprint {
		t.Fatalf("keyring fingerprints = %#v", got.KeyringFingerprints)
	}

	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(exec.commands))
	}

	command := exec.commands[0]
	if !strings.Contains(
		command,
		"SUDO_LABEL["+aptListDoctorProbeLabel+"]: ",
	) {
		t.Fatalf("probe label missing from command: %s", command)
	}

	for _, expected := range []string{
		`SOURCE_FILE="/etc/apt/sources.list.d/hashicorp.list"`,
		`KEYRING_PATH="/usr/share/keyrings/hashicorp-archive-keyring.gpg"`,
		"stat -c",
		"command -v apt-get",
		"command -v gpg",
		"--no-default-keyring",
		"--with-colons --list-keys",
		aptListDoctorProbeBegin,
		aptListDoctorProbeEnd,
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("probe command missing %q:\n%s", expected, command)
		}
	}

	for _, forbidden := range []string{
		"apt-get update",
		"apt-get install",
		"curl ",
		"wget ",
		"gpg --dearmor",
		"gpg --import",
		"mv ",
		"cp ",
		"rm ",
		"chmod ",
		"chown ",
		"touch ",
		"mkdir ",
		"mktemp",
		"base64 --",
		"cat ",
		"> /etc/",
		"> /var/",
		"> /tmp/",
		"> ./",
	} {
		if strings.Contains(command, forbidden) {
			t.Fatalf(
				"probe command must not contain %q:\n%s",
				forbidden,
				command,
			)
		}
	}
}

func TestProbeSelectedAPTListRepairMetadataRejectsUnsafeActionWithoutCommand(
	t *testing.T,
) {
	action := aptListDoctorProbeAction()
	action.SourceFile = "/tmp/hashicorp.list"

	exec := &fakeExecutor{}
	_, err := ProbeSelectedAPTListRepairMetadata(exec, action)

	if err == nil {
		t.Fatal("unsafe action unexpectedly started remote probe")
	}
	if !strings.Contains(err.Error(), "outside approved APT list paths") {
		t.Fatalf("error = %q", err.Error())
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unsafe action issued commands: %#v", exec.commands)
	}
}

func TestProbeSelectedAPTListRepairMetadataRejectsUnverifiedProfileWithoutCommand(
	t *testing.T,
) {
	action := aptListDoctorProbeAction()
	action.ProfileID = "unknown"

	exec := &fakeExecutor{}
	_, err := ProbeSelectedAPTListRepairMetadata(exec, action)

	if err == nil {
		t.Fatal("unverified action unexpectedly started remote probe")
	}
	if !strings.Contains(err.Error(), "verified HashiCorp profile") {
		t.Fatalf("error = %q", err.Error())
	}
	if len(exec.commands) != 0 {
		t.Fatalf("unverified action issued commands: %#v", exec.commands)
	}
}

func TestProbeSelectedAPTListRepairMetadataRejectsMalformedOutput(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeBegin +
				"\napt_get|present\n" +
				aptListDoctorProbeEnd,
		},
	}

	_, err := ProbeSelectedAPTListRepairMetadata(
		exec,
		aptListDoctorProbeAction(),
	)
	if err == nil {
		t.Fatal("malformed probe output unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "invalid probe output envelope") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestProbeSelectedAPTListRepairMetadataRejectsFingerprintWithoutGPG(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeOutput(
				"present",
				"missing",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
				HashiCorpAPTListExpectedFingerprint,
			),
		},
	}

	_, err := ProbeSelectedAPTListRepairMetadata(
		exec,
		aptListDoctorProbeAction(),
	)
	if err == nil {
		t.Fatal("fingerprints without gpg unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "fingerprints reported without gpg") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestProbeSelectedAPTListRepairMetadataRejectsTransportFailure(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoLabelOutputs: []string{
			aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
			),
		},
		runSudoLabelErrors: []error{errors.New("ssh transport failed")},
	}

	_, err := ProbeSelectedAPTListRepairMetadata(
		exec,
		aptListDoctorProbeAction(),
	)
	if err == nil {
		t.Fatal("transport error unexpectedly succeeded")
	}
	if !strings.Contains(
		err.Error(),
		"APT list Doctor remote probe failed: ssh transport failed",
	) {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestParseAPTListDoctorProbeOutputRejectsUnsafeRecords(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name: "Unknown record",
			output: strings.Join([]string{
				aptListDoctorProbeBegin,
				"apt_get|present",
				"gpg|present",
				"file|source|present|644|1",
				"file|keyring|present|644|2",
				"extra|value",
				aptListDoctorProbeEnd,
			}, "\n"),
		},
		{
			name: "Duplicate file",
			output: strings.Join([]string{
				aptListDoctorProbeBegin,
				"apt_get|present",
				"gpg|present",
				"file|source|present|644|1",
				"file|source|present|644|1",
				"file|keyring|present|644|2",
				aptListDoctorProbeEnd,
			}, "\n"),
		},
		{
			name: "Invalid fingerprint",
			output: aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
				"not-a-fingerprint",
			),
		},
		{
			name: "Short fingerprint",
			output: aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"644",
				"1",
				"present",
				"644",
				"2",
				"FC9CA96ACA026560",
			),
		},
		{
			name: "Missing source metadata",
			output: aptListDoctorProbeOutput(
				"present",
				"present",
				"present",
				"",
				"",
				"present",
				"644",
				"2",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseAPTListDoctorProbeOutput(test.output)
			if err == nil {
				t.Fatal("unsafe probe record unexpectedly parsed")
			}
		})
	}
}

func TestAPTListDoctorRemoteProbeSourceRemainsReadOnly(t *testing.T) {
	source, err := os.ReadFile("apt_list_doctor_probe.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	code := string(source)

	for _, required := range []string{
		"gpg --batch --no-options --no-default-keyring",
		"--with-colons --list-keys",
		"stat -c",
		"command -v apt-get",
		"command -v gpg",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"APT list Doctor remote probe source missing %q",
				required,
			)
		}
	}

	for _, forbidden := range []string{
		"apt-get update",
		"apt-get install",
		"apt update",
		"apt install",
		"curl ",
		"wget ",
		"gpg --dearmor",
		"gpg --import",
		"apt-key",
		"mv ",
		"cp ",
		"rm ",
		"chmod ",
		"chown ",
		"touch ",
		"mkdir ",
		"mktemp",
		"base64 --",
		"> /etc/",
		"> /var/",
		"> /tmp/",
		"> ./",
		"RunSudo(",
		"CreateAPTFileSnapshot(",
		"AppendDeb822RepairAuditEvent(",
		"ApproveAndApplyAPTRepair(",
		"ApplyDeb822RepairExecution(",
	} {
		if strings.Contains(code, forbidden) {
			t.Fatalf(
				"APT list Doctor remote probe must remain read-only; found %q",
				forbidden,
			)
		}
	}
}
