package repohealer

import (
	"strings"
	"testing"
)

func TestAPTAdapterDiagnoseFindsKnownDockerKeyringBindingMismatch(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			`=== APT_SOURCES ===
/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/old-docker.gpg] https://download.docker.com/linux/debian bookworm stable
=== SIGNED_BY_REFERENCES ===
/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/old-docker.gpg] https://download.docker.com/linux/debian bookworm stable
=== KEYRINGS ===
/etc/apt/keyrings/old-docker.gpg        644     root:root
`,
			"",
			"PRESENT\n",
		},
	}

	adapter := APTAdapter{}
	_, findings, actions := adapter.Diagnose(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		DefaultDiagnosticPolicy(),
	)

	if len(actions) != 0 {
		t.Fatalf("diagnosis must not execute or create adapter actions, got %d", len(actions))
	}

	var mismatch Finding
	found := false
	for _, finding := range findings {
		if finding.Code == "APT_SOURCE_KEYRING_MISMATCH" {
			mismatch = finding
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected Docker keyring binding mismatch; findings: %#v", findings)
	}
	if mismatch.RepositoryName != "Docker CE" {
		t.Fatalf("repository name = %q, want Docker CE", mismatch.RepositoryName)
	}
	if mismatch.RepositoryURL != "https://download.docker.com/linux/debian" {
		t.Fatalf("repository URL = %q", mismatch.RepositoryURL)
	}
	if mismatch.SourceFile != "/etc/apt/sources.list.d/docker.list" {
		t.Fatalf("source file = %q", mismatch.SourceFile)
	}
	if mismatch.SourceLine != 1 {
		t.Fatalf("source line = %d, want 1", mismatch.SourceLine)
	}
	if mismatch.Risk != RiskKnownVendor {
		t.Fatalf("risk = %q, want %q", mismatch.Risk, RiskKnownVendor)
	}
	if !mismatch.AutoRepairable {
		t.Fatal("known Docker keyring mismatch must be auto-repairable after approval")
	}
	if !mismatch.RequiresConsent {
		t.Fatal("known Docker keyring mismatch must require explicit approval")
	}
	if !strings.Contains(mismatch.Evidence, "/etc/apt/keyrings/old-docker.gpg") {
		t.Fatalf("evidence must include observed keyring path: %s", mismatch.Evidence)
	}
	if !strings.Contains(mismatch.Evidence, "/etc/apt/keyrings/docker.gpg") {
		t.Fatalf("evidence must include expected keyring path: %s", mismatch.Evidence)
	}
	if len(exec.commands) != 3 {
		t.Fatalf(
			"expected inventory, apt update, and readable-keyring check; got %d commands",
			len(exec.commands),
		)
	}
	if strings.Contains(exec.commands[2], "sed -n") {
		t.Fatalf(
			"readable mismatch must not read source line again; got command:\n%s",
			exec.commands[2],
		)
	}
}

func TestAPTAdapterDiagnoseDoesNotFlagMatchingDockerKeyringBinding(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			`=== SIGNED_BY_REFERENCES ===
/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable
=== KEYRINGS ===
/etc/apt/keyrings/docker.gpg    644     root:root
`,
			"",
			"PRESENT\n",
		},
	}

	adapter := APTAdapter{}
	_, findings, _ := adapter.Diagnose(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		DefaultDiagnosticPolicy(),
	)

	for _, finding := range findings {
		if finding.Code == "APT_SOURCE_KEYRING_MISMATCH" {
			t.Fatalf("matching Docker keyring must not be flagged: %#v", finding)
		}
		if finding.Code == "APT_KEYRING_PATH_MISSING" {
			t.Fatalf("readable Docker keyring must not be flagged missing: %#v", finding)
		}
	}

	if len(exec.commands) != 3 {
		t.Fatalf(
			"expected inventory, apt update, and readable-keyring check; got %d commands",
			len(exec.commands),
		)
	}
}

func TestAPTAdapterDiagnoseKeepsMissingDockerKeyringAsMissingFinding(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			`=== SIGNED_BY_REFERENCES ===
/etc/apt/sources.list.d/docker.list:1:deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable
`,
			"",
			"MISSING\n",
		},
	}

	adapter := APTAdapter{}
	_, findings, _ := adapter.Diagnose(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		DefaultDiagnosticPolicy(),
	)

	foundMissing := false
	for _, finding := range findings {
		switch finding.Code {
		case "APT_KEYRING_PATH_MISSING":
			foundMissing = true
		case "APT_SOURCE_KEYRING_MISMATCH":
			t.Fatalf("missing Docker keyring must not be reported as mismatch: %#v", finding)
		}
	}

	if !foundMissing {
		t.Fatalf("expected missing Docker keyring finding; findings: %#v", findings)
	}

	var missing Finding
	for _, finding := range findings {
		if finding.Code == "APT_KEYRING_PATH_MISSING" {
			missing = finding
			break
		}
	}

	if missing.RepositoryName != "Docker CE" {
		t.Fatalf("repository name = %q, want Docker CE", missing.RepositoryName)
	}
	if missing.Risk != RiskKnownVendor {
		t.Fatalf("risk = %q, want %q", missing.Risk, RiskKnownVendor)
	}
	if !missing.AutoRepairable {
		t.Fatal("known Docker missing keyring must be auto-repairable after approval")
	}
	if !missing.RequiresConsent {
		t.Fatal("known Docker missing keyring must require explicit approval")
	}

	if len(exec.commands) != 3 {
		t.Fatalf(
			"expected inventory, apt update, and keyring check; got %d commands",
			len(exec.commands),
		)
	}
	if strings.Contains(exec.commands[2], "sed -n") {
		t.Fatalf("missing keyring path must use parsed source reference; got:\n%s", exec.commands[2])
	}
}

func TestAPTAdapterDiagnoseFindsKnownDockerDeb822KeyringMismatch(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			`=== DEB822_SOURCES ===
--- DEB822_FILE_BEGIN ---
/etc/apt/sources.list.d/docker.sources
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/old-docker.gpg
--- DEB822_FILE_END ---
=== KEYRINGS ===
/etc/apt/keyrings/old-docker.gpg        644     root:root
`,
			"",
			"PRESENT\n",
		},
	}

	adapter := APTAdapter{}
	_, findings, _ := adapter.Diagnose(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "parrot",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		DefaultDiagnosticPolicy(),
	)

	var mismatch Finding
	found := false
	for _, finding := range findings {
		if finding.Code == "APT_SOURCE_KEYRING_MISMATCH" &&
			finding.SourceFile == "/etc/apt/sources.list.d/docker.sources" {
			mismatch = finding
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected Deb822 Docker keyring mismatch; findings: %#v", findings)
	}
	if mismatch.RepositoryName != "Docker CE" {
		t.Fatalf("repository name = %q, want Docker CE", mismatch.RepositoryName)
	}
	if mismatch.RepositoryURL != "https://download.docker.com/linux/debian" {
		t.Fatalf("repository URL = %q", mismatch.RepositoryURL)
	}
	if mismatch.SourceLine != 1 {
		t.Fatalf("stanza start line = %d, want 1", mismatch.SourceLine)
	}
	if mismatch.Risk != RiskKnownVendor {
		t.Fatalf("risk = %q, want %q", mismatch.Risk, RiskKnownVendor)
	}
	if !mismatch.AutoRepairable {
		t.Fatal("known Deb822 Docker mismatch must be eligible after approval")
	}
	if !mismatch.RequiresConsent {
		t.Fatal("known Deb822 Docker mismatch must require approval")
	}

	if len(exec.commands) != 3 {
		t.Fatalf(
			"expected inventory, apt update, and keyring check; got %d commands",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[0], "DEB822_SOURCES") ||
		!strings.Contains(exec.commands[0], "--- DEB822_FILE_BEGIN ---") {
		t.Fatalf(
			"inventory command must collect complete Deb822 source files:\n%s",
			exec.commands[0],
		)
	}
}

func TestAPTAdapterDiagnoseBuildsBlockedHashiCorpAPTListDoctorAction(
	t *testing.T,
) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			`=== APT_SOURCES ===
/etc/apt/sources.list.d/hashicorp.list:1:deb [arch=amd64 signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main
=== SIGNED_BY_REFERENCES ===
/etc/apt/sources.list.d/hashicorp.list:1:deb [arch=amd64 signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com lory main
=== DEB822_SOURCES ===
=== KEYRINGS ===
/usr/share/keyrings/hashicorp-archive-keyring.gpg	644	root:root
=== DPKG_AUDIT ===
=== LOCK_OWNERS ===
=== STORAGE ===
=== TIME ===`,
			`Err:1 https://apt.releases.hashicorp.com lory InRelease
  The following signatures couldn't be verified because the public key is not available: NO_PUBKEY FC9CA96ACA026560`,
			"PRESENT\n",
		},
	}

	adapter := APTAdapter{}

	_, findings, actions := adapter.Diagnose(
		exec,
		TargetFacts{
			Platform:       PlatformLinux,
			Distribution:   "debian",
			Version:        "6.4",
			Codename:       "lory",
			Architecture:   "amd64",
			PackageManager: ManagerAPT,
		},
		DefaultDiagnosticPolicy(),
	)

	var missingKeyFound bool
	for _, finding := range findings {
		if finding.Code == "APT_REPO_KEY_MISSING" &&
			strings.Contains(finding.Evidence, "FC9CA96ACA026560") {
			missingKeyFound = true
			break
		}
	}

	if !missingKeyFound {
		t.Fatalf("findings = %#v, want NO_PUBKEY HashiCorp finding", findings)
	}

	if len(actions) != 1 {
		t.Fatalf("action count = %d, want 1: %#v", len(actions), actions)
	}

	action := actions[0]

	if action.ID != "apt-keyring-repair-hashicorp" {
		t.Fatalf("action ID = %q", action.ID)
	}
	if action.FindingCode != "APT_REPO_KEY_MISSING" {
		t.Fatalf("finding code = %q", action.FindingCode)
	}
	if action.Eligible {
		t.Fatal("HashiCorp Doctor action must be blocked from repair")
	}
	if action.RequiresConsent {
		t.Fatal("HashiCorp Doctor action must not request repair consent")
	}
	if action.Risk != RiskBlocked {
		t.Fatalf("risk = %q, want %q", action.Risk, RiskBlocked)
	}
	if action.ProfileID != HashiCorpAPTListProfileID {
		t.Fatalf("profile ID = %q", action.ProfileID)
	}
	if action.RepositoryURL != HashiCorpAPTListRepositoryURL {
		t.Fatalf("repository URL = %q", action.RepositoryURL)
	}
	if action.SourceFile != "/etc/apt/sources.list.d/hashicorp.list" {
		t.Fatalf("source file = %q", action.SourceFile)
	}
	if action.SourceLine != 1 {
		t.Fatalf("source line = %d, want 1", action.SourceLine)
	}
	if action.SourceFormat != SourceFormatAPTList {
		t.Fatalf("source format = %q", action.SourceFormat)
	}
	if action.KeyringPath != HashiCorpAPTListKeyringPath {
		t.Fatalf("keyring path = %q", action.KeyringPath)
	}
	if len(action.Commands) != 0 ||
		len(action.Verification) != 0 ||
		len(action.Rollback) != 0 ||
		len(action.SnapshotTargets) != 0 {
		t.Fatalf(
			"Doctor action must contain no mutation plan: %#v",
			action,
		)
	}
}
