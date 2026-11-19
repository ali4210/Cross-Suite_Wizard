package repohealer

// Tests for the new vendor profiles added to KnownVendorProfiles: Sensu, Grafana,
// NodeSource, Kubernetes (v1.31), MongoDB (9.0), Brave, Mozilla, Tailscale, Cloudflare,
// Elastic, and Zabbix (7.0).
//
// TestNewVendorProfilesResolveAndRenderExpectedSourceLine is a pure-function unit test:
// it checks FindVendorProfile resolves the real repository URL each vendor documents, and
// that RenderAPTSource (or, for Jenkins/Kubernetes-style flat repos, the same function)
// reproduces the exact source line captured from each vendor's own documentation/install
// script during verification.
//
// TestNewVendorProfileKeysDownloadAndMatchPinnedFingerprintInRealContainer re-downloads
// every one of these profiles' KeyURL for real, inside a real ubuntu:24.04 Docker
// container, and confirms the pinned ExpectedFingerprints value is actually present in
// what's downloaded today — not just trusting that it still matches what was captured
// during manual verification. It skips cleanly (not fails) when Docker isn't available or
// this isn't a Linux host.

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestNewVendorProfilesResolveAndRenderExpectedSourceLine(t *testing.T) {
	arch := "amd64"

	cases := []struct {
		name        string
		manager     PackageManager
		lookupURL   string
		wantID      string
		input       SourceRenderInput
		wantAPTLine string
	}{
		{
			name:        "Grafana",
			manager:     ManagerAPT,
			lookupURL:   "https://apt.grafana.com",
			wantID:      "grafana",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main",
		},
		{
			name:        "NodeSource",
			manager:     ManagerAPT,
			lookupURL:   "https://deb.nodesource.com/node_22.x",
			wantID:      "nodesource",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main",
		},
		{
			name:        "Mozilla",
			manager:     ManagerAPT,
			lookupURL:   "https://packages.mozilla.org/apt",
			wantID:      "mozilla",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/mozilla.gpg] https://packages.mozilla.org/apt mozilla main",
		},
		{
			name:        "Brave",
			manager:     ManagerAPT,
			lookupURL:   "https://brave-browser-apt-release.s3.brave.com",
			wantID:      "brave",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com stable main",
		},
		{
			name:        "Sensu noble",
			manager:     ManagerAPT,
			lookupURL:   "https://packagecloud.io/sensu/stable/ubuntu",
			wantID:      "sensu",
			input:       SourceRenderInput{Architecture: arch, Codename: "noble"},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/sensu.gpg] https://packagecloud.io/sensu/stable/ubuntu noble main",
		},
		{
			name:        "Zabbix 7.0 noble",
			manager:     ManagerAPT,
			lookupURL:   "https://repo.zabbix.com/zabbix/7.0/ubuntu",
			wantID:      "zabbix",
			input:       SourceRenderInput{Architecture: arch, Codename: "noble"},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/zabbix.gpg] https://repo.zabbix.com/zabbix/7.0/ubuntu noble main",
		},
		{
			name:        "Tailscale jammy",
			manager:     ManagerAPT,
			lookupURL:   "https://pkgs.tailscale.com/stable/ubuntu",
			wantID:      "tailscale",
			input:       SourceRenderInput{Architecture: arch, Codename: "jammy"},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/tailscale.gpg] https://pkgs.tailscale.com/stable/ubuntu jammy main",
		},
		{
			name:        "Cloudflare noble",
			manager:     ManagerAPT,
			lookupURL:   "https://pkg.cloudflare.com/cloudflared",
			wantID:      "cloudflare",
			input:       SourceRenderInput{Architecture: arch, Codename: "noble"},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared noble main",
		},
		{
			name:        "MongoDB 9.0 noble",
			manager:     ManagerAPT,
			lookupURL:   "https://repo.mongodb.org/apt/ubuntu",
			wantID:      "mongodb",
			input:       SourceRenderInput{Architecture: arch, Codename: "noble"},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/mongodb-server-9.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/9.0 multiverse",
		},
		{
			name:        "Kubernetes v1.31",
			manager:     ManagerAPT,
			lookupURL:   "https://pkgs.k8s.io/core:/stable:/v1.31/deb/",
			wantID:      "kubernetes-v1-31",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /",
		},
		{
			name:        "Elastic 9.x",
			manager:     ManagerAPT,
			lookupURL:   "https://artifacts.elastic.co/packages/9.x/apt",
			wantID:      "elastic",
			input:       SourceRenderInput{Architecture: arch},
			wantAPTLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			profile, ok := FindVendorProfile(c.manager, c.lookupURL)
			if !ok {
				t.Fatalf("expected a vendor profile to be found for %q", c.lookupURL)
			}
			if profile.ID != c.wantID {
				t.Fatalf("profile ID = %q, want %q", profile.ID, c.wantID)
			}
			if profile.DocSource == "" {
				t.Fatalf("profile %q has no DocSource", profile.ID)
			}
			if len(profile.ExpectedFingerprints) == 0 {
				t.Fatalf("profile %q pins no fingerprints", profile.ID)
			}

			got, err := RenderAPTSource(profile, c.input)
			if err != nil {
				t.Fatalf("RenderAPTSource(%q) returned error: %v", profile.ID, err)
			}
			if got != c.wantAPTLine {
				t.Fatalf("RenderAPTSource(%q) = %q, want %q", profile.ID, got, c.wantAPTLine)
			}
		})
	}
}

func TestZabbixAndSensuRejectUnsupportedCodename(t *testing.T) {
	for _, id := range []string{"zabbix", "sensu", "mongodb"} {
		profile, ok := FindVendorProfileByID(ManagerAPT, id)
		if !ok {
			t.Fatalf("profile %q not found", id)
		}
		_, err := RenderAPTSource(profile, SourceRenderInput{Architecture: "amd64", Codename: "totally-unsupported-codename"})
		if err == nil {
			t.Fatalf("expected %q to reject an unsupported codename", id)
		}
	}
}

// TestNewVendorProfileKeysDownloadAndMatchPinnedFingerprintInRealContainer re-downloads
// every new profile's KeyURL for real inside a real ubuntu:24.04 Docker container (running
// the exact dearmor step the real repair pipeline uses — see apt_repair.go) and confirms
// the pinned fingerprint is actually present in what's downloaded today.
func TestNewVendorProfileKeysDownloadAndMatchPinnedFingerprintInRealContainer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: real-container key verification needs a Linux Docker host")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: docker not found on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("skipping: docker daemon not reachable on this runner")
	}

	ids := []string{
		"grafana", "nodesource", "mozilla", "brave", "sensu", "zabbix",
		"tailscale", "cloudflare", "mongodb", "kubernetes-v1-31", "elastic",
	}

	var script strings.Builder
	script.WriteString("set -e\n")
	script.WriteString("apt-get -o Acquire::Check-Date=false update -qq >/dev/null\n")
	script.WriteString("apt-get install -y -qq gnupg curl ca-certificates >/dev/null\n")
	for _, id := range ids {
		profile, ok := FindVendorProfileByID(ManagerAPT, id)
		if !ok {
			t.Fatalf("profile %q not found in catalog", id)
		}
		fmt.Fprintf(&script, "echo '=== %s ==='\n", id)
		fmt.Fprintf(&script, "curl -fsSL '%s' -o /tmp/%s.key\n", profile.KeyURL, id)
		fmt.Fprintf(&script, "gpg --dearmor --yes --output /tmp/%s.gpg /tmp/%s.key 2>/dev/null\n", id, id)
		fmt.Fprintf(&script, "gpg --show-keys --with-colons --with-fingerprint /tmp/%s.gpg 2>/dev/null | grep '^fpr'\n", id)
	}

	cmd := exec.Command("docker", "run", "--rm", "ubuntu:24.04", "bash", "-c", script.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\noutput:\n%s", err, out)
	}
	output := string(out)

	// Split the output into per-vendor sections and confirm each profile's pinned
	// fingerprint appears in that vendor's section of the real, freshly-downloaded key.
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
		profile, _ := FindVendorProfileByID(ManagerAPT, id)
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
