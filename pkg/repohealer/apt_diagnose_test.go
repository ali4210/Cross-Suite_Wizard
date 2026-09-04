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
/etc/apt/keyrings/old-docker.gpg	644	root:root
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
/etc/apt/keyrings/docker.gpg	644	root:root
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
			"deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable\n",
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

	if len(exec.commands) != 4 {
		t.Fatalf(
			"expected inventory, apt update, keyring check, source-line read; got %d commands",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[3], "sed -n '1p'") {
		t.Fatalf("missing keyring path must read the source line; got:\n%s", exec.commands[3])
	}
}
