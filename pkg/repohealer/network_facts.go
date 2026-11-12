package repohealer

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CollectNetworkFacts runs lightweight, read-only checks for the most common non-repository
// causes of package-manager failures — DNS resolution, an active proxy, clock skew, and low
// disk space — and turns anything suspicious into a Finding so every adapter benefits from
// the same pre-check without duplicating it.
func CollectNetworkFacts(exec Executor) ([]CommandEvidence, []Finding) {
	const script = `
set +e
echo '=== DNS ==='
getent hosts github.com 2>&1 || nslookup github.com 2>&1 || true
echo '=== PROXY ==='
env | grep -i '_proxy=' 2>/dev/null
echo '=== CLOCK ==='
date -u +%s
echo '=== DISK ==='
df -Pk / 2>/dev/null | tail -n 1
echo '=== CLEANUP ==='
du -sh /var/cache/apt/archives 2>/dev/null
find /var/log -type f -printf '%s\t%p\n' 2>/dev/null | sort -rn | head -n 5 \
  | awk -F'\t' '{printf "%.1fM\t%s\n", $1/1048576, $2}'
`
	started := time.Now()
	output, err := exec.Run(script)
	exitCode := 0
	if err != nil {
		exitCode = 1
	}

	evidence := []CommandEvidence{{
		Command:  "network/proxy/clock/disk pre-check",
		Output:   strings.TrimSpace(output),
		ExitCode: exitCode,
		Duration: time.Since(started),
	}}

	var findings []Finding
	sections := splitNetworkFactSections(output)

	dns := strings.ToLower(sections["DNS"])
	if strings.TrimSpace(dns) == "" ||
		strings.Contains(dns, "not found") ||
		strings.Contains(dns, "no servers could be reached") ||
		strings.Contains(dns, "nxdomain") ||
		strings.Contains(dns, "can't resolve") {
		findings = append(findings, Finding{
			Code:            "NETWORK_DNS_RESOLUTION_FAILED",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "DNS resolution for a known-good hostname failed, which will make every package manager's update/sync step fail too.",
			RecommendedFix:  "Check /etc/resolv.conf, the network connection, and any VPN/DNS override before retrying repository operations.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	if proxy := strings.TrimSpace(sections["PROXY"]); proxy != "" {
		findings = append(findings, Finding{
			Code:            "NETWORK_PROXY_ACTIVE",
			Severity:        SeverityInfo,
			Risk:            RiskManual,
			Evidence:        "An http_proxy/https_proxy environment variable is set: " + proxy,
			RecommendedFix:  "If repository operations fail with connection or TLS errors, confirm the proxy is reachable and that the package manager is configured to use it.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	if detectClockSkew(sections["CLOCK"]) {
		findings = append(findings, Finding{
			Code:            "NETWORK_CLOCK_SKEW_SUSPECTED",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "The target host's clock appears to differ significantly from this controller's clock, which can cause TLS/GPG signature validation failures.",
			RecommendedFix:  "Verify NTP/time sync is active on the target host before treating a TLS or signature error as a repository problem.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	if diskLine := strings.TrimSpace(sections["DISK"]); detectDiskFull(diskLine) {
		evidence := fmt.Sprintf(
			"The root filesystem is at or near capacity, which causes package-manager cache/download/unpack "+
				"failures that look like repository corruption.\ndf -Pk / output: %s",
			diskLine,
		)
		if cleanup := strings.TrimSpace(sections["CLEANUP"]); cleanup != "" {
			evidence += "\nLargest read-only-identified cleanup candidates (apt cache, largest log files; nothing was deleted):\n" +
				formatAPTInventoryEvidenceLines(strings.Split(cleanup, "\n"))
		}

		findings = append(findings, Finding{
			Code:            "NETWORK_DISK_SPACE_LOW",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        evidence,
			RecommendedFix:  "Free up disk space before retrying any repair (e.g. `apt-get clean`, or remove the largest old logs shown above) — package managers fail unpredictably when the disk is full. This tool never deletes anything automatically.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return evidence, findings
}

func splitNetworkFactSections(output string) map[string]string {
	sections := map[string]string{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "=== ") && strings.HasSuffix(trimmed, " ===") {
			current = strings.TrimSuffix(strings.TrimPrefix(trimmed, "=== "), " ===")
			continue
		}
		if current == "" {
			continue
		}
		sections[current] += line + "\n"
	}
	return sections
}

func detectClockSkew(clockSection string) bool {
	remoteUnix, err := strconv.ParseInt(strings.TrimSpace(clockSection), 10, 64)
	if err != nil {
		return false
	}
	skew := time.Now().UTC().Unix() - remoteUnix
	if skew < 0 {
		skew = -skew
	}
	return skew > 300
}

func detectDiskFull(diskSection string) bool {
	fields := strings.Fields(strings.TrimSpace(diskSection))
	if len(fields) < 5 {
		return false
	}
	capacity, err := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
	if err != nil {
		return false
	}
	return capacity >= 97
}
