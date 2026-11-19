package repohealer

// TestRPMVendorProfileKeysDownloadAndMatchPinnedFingerprintInRealContainer re-downloads
// every RPM (dnf/yum/zypper) vendor profile's KeyURL for real, inside a real Fedora 45
// (dnf) and openSUSE Leap 16.0 (zypper) Docker container, and confirms the pinned
// ExpectedFingerprints value is actually present in what's downloaded today — not just
// trusting the fingerprint captured during manual verification. Skips cleanly (not fails)
// when Docker isn't available or this isn't a Linux host.

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestRPMVendorProfileKeysDownloadAndMatchPinnedFingerprintInRealContainer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: real-container key verification needs a Linux Docker host")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: docker not found on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("skipping: docker daemon not reachable on this runner")
	}

	t.Run("dnf/Fedora", func(t *testing.T) {
		dnfIDs := []string{
			"hashicorp", "docker-ce", "microsoft-rpm", "google-chrome-rpm",
			"postgresql-pgdg-rpm", "github-cli-rpm", "sensu-rpm", "tailscale-rpm",
			"cloudflare-rpm", "elastic-rpm", "jenkins-rpm", "zabbix-rpm", "brave-rpm",
			"kubernetes-v1-31-rpm", "mongodb-rpm", "nodesource-rpm", "grafana-rpm",
		}
		verifyRPMProfileKeysInContainer(t, "fedora:latest", "gnupg2 curl", ManagerDNF, dnfIDs)
	})

	t.Run("zypper/openSUSE", func(t *testing.T) {
		zypperIDs := []string{
			"google-chrome-rpm", "postgresql-pgdg-rpm-suse", "github-cli-rpm",
			"elastic-rpm", "jenkins-rpm", "kubernetes-v1-31-rpm",
		}
		verifyRPMProfileKeysInContainer(t, "opensuse/leap:latest", "gpg2 curl", ManagerZypper, zypperIDs)
	})
}

func verifyRPMProfileKeysInContainer(t *testing.T, image, installPackages string, manager PackageManager, ids []string) {
	t.Helper()

	var script strings.Builder
	script.WriteString("set -e\n")
	if manager == ManagerZypper {
		fmt.Fprintf(&script, "zypper --non-interactive install -y %s >/dev/null 2>&1 || true\n", installPackages)
	} else {
		fmt.Fprintf(&script, "dnf install -y %s >/dev/null 2>&1\n", installPackages)
	}
	for _, id := range ids {
		profile, ok := FindVendorProfileByID(manager, id)
		if !ok {
			t.Fatalf("profile %q not found in catalog for manager %v", id, manager)
		}
		fmt.Fprintf(&script, "echo '=== %s ==='\n", id)
		fmt.Fprintf(&script, "curl -fsSL '%s' -o /tmp/%s.key\n", profile.KeyURL, id)
		fmt.Fprintf(&script, "gpg --show-keys --with-colons --with-fingerprint /tmp/%s.key 2>/dev/null | grep '^fpr'\n", id)
	}

	cmd := exec.Command("docker", "run", "--rm", image, "bash", "-c", script.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\noutput:\n%s", err, out)
	}
	output := string(out)

	sections := map[string]string{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "=== ") && strings.HasSuffix(trimmed, " ===") {
			current = strings.TrimSuffix(strings.TrimPrefix(trimmed, "=== "), " ===")
			continue
		}
		if current != "" {
			sections[current] += line + "\n"
		}
	}

	for _, id := range ids {
		profile, _ := FindVendorProfileByID(manager, id)
		section := sections[id]
		if section == "" {
			t.Errorf("no output captured for profile %q (full output:\n%s)", id, output)
			continue
		}
		for _, expected := range profile.ExpectedFingerprints {
			if !strings.Contains(strings.ToUpper(section), strings.ToUpper(expected)) {
				t.Errorf("profile %q: pinned fingerprint %s not found in freshly-downloaded key today:\n%s", id, expected, section)
			}
		}
	}
}
