package repohealer

import (
	"strings"
	"testing"
)

func TestFormatDeb822RepairInspectionForReadyInspection(t *testing.T) {
	output := FormatDeb822RepairInspection(Deb822RepairInspection{
		ActionID:    "apt-keyring-repair-docker-ce",
		ProfileID:   "docker-ce",
		ProfileName: "Docker CE",
		SourceFile:  "/etc/apt/sources.list.d/docker.sources",
		KeyringPath: "/etc/apt/keyrings/docker.gpg",
		SnapshotTargets: []string{
			"/etc/apt/sources.list.d/docker.sources",
			"/etc/apt/keyrings/docker.gpg",
		},
		RenderedSource: `Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.gpg
`,
		Ready: true,
	})

	for _, expected := range []string{
		"Deb822 Repository Repair Inspection",
		"Status: Ready for review — no repair will run",
		"Action: apt-keyring-repair-docker-ce",
		"Profile: Docker CE (docker-ce)",
		"Source: /etc/apt/sources.list.d/docker.sources",
		"Keyring: /etc/apt/keyrings/docker.gpg",
		"Rendered replacement:",
		"Types: deb",
		"URIs: https://download.docker.com/linux/debian",
		"Signed-By: /etc/apt/keyrings/docker.gpg",
		"Future snapshot targets:",
		"/etc/apt/sources.list.d/docker.sources",
		"/etc/apt/keyrings/docker.gpg",
		"Inspection only: no repair was executed.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf(
				"ready inspection output missing %q:\n%s",
				expected,
				output,
			)
		}
	}

	for _, unexpected := range []string{
		"Repair output:",
		"Verification output:",
		"apt-get update",
		"curl ",
		"gpg ",
	} {
		if strings.Contains(output, unexpected) {
			t.Fatalf(
				"ready inspection output must not contain %q:\n%s",
				unexpected,
				output,
			)
		}
	}
}

func TestFormatDeb822RepairInspectionForBlockedInspection(t *testing.T) {
	output := FormatDeb822RepairInspection(Deb822RepairInspection{
		ActionID:    "apt-keyring-repair-docker-ce",
		ProfileID:   "docker-ce",
		ProfileName: "Docker CE",
		SourceFile:  "/etc/apt/sources.list.d/docker.sources",
		KeyringPath: "/etc/apt/keyrings/docker.gpg",
		BlockReason: "Deb822 source read blocked: symlink",
	})

	for _, expected := range []string{
		"Deb822 Repository Repair Inspection",
		"Status: Blocked — no repair will run",
		"Action: apt-keyring-repair-docker-ce",
		"Profile: Docker CE (docker-ce)",
		"Reason: Deb822 source read blocked: symlink",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf(
				"blocked inspection output missing %q:\n%s",
				expected,
				output,
			)
		}
	}

	for _, unexpected := range []string{
		"Rendered replacement:",
		"Future snapshot targets:",
		"Inspection only:",
		"Source: /etc/apt/sources.list.d/docker.sources",
		"Keyring: /etc/apt/keyrings/docker.gpg",
	} {
		if strings.Contains(output, unexpected) {
			t.Fatalf(
				"blocked inspection output must not expose %q:\n%s",
				unexpected,
				output,
			)
		}
	}
}
