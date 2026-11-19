package repohealer

import "strings"

// discoverKnownRPMVendorRepo looks at the target's currently-configured repositories and
// returns the first one whose baseurl matches a known vendor RPM profile for the given
// manager — the piece dnf.go/zypper.go's diagnose needs so a GPG-failure finding can be
// attributed to a specific vendor profile (APT's diagnose does the equivalent by parsing
// .list/.sources files directly; dnf/zypper's current probe only looks at aggregate
// makecache/refresh output, with no per-repository breakdown, so this adds exactly that).
func discoverKnownRPMVendorRepo(manager PackageManager, listOutput string) (VendorProfile, string, bool) {
	for _, baseurl := range extractRPMRepoBaseURLs(manager, listOutput) {
		if profile, ok := FindVendorProfile(canonicalRPMManager(manager), baseurl); ok {
			return profile, profile.RPMRepoFile, true
		}
	}
	return VendorProfile{}, "", false
}

// canonicalRPMManager maps YUM to DNF for vendor-profile lookups: yum is dnf's
// functionally-identical legacy alias on every modern target (RHEL/Fedora), and this
// catalog registers RPM vendor profiles once, under ManagerDNF, rather than duplicating
// every entry under ManagerYUM too.
func canonicalRPMManager(manager PackageManager) PackageManager {
	if manager == ManagerYUM {
		return ManagerDNF
	}
	return manager
}

// extractRPMRepoBaseURLs parses the configured baseurls out of either dnf's `repoinfo`
// output (a "Base URL" line per repo) or zypper's `lr -u` table output (a URI column),
// covering both shapes without needing to read .repo files directly over a second
// remote round trip.
func extractRPMRepoBaseURLs(manager PackageManager, output string) []string {
	var urls []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		switch manager {
		case ManagerZypper:
			// zypper lr -u table row: "# | Alias | Name | Enabled | GPG Check | Refresh | URI"
			if strings.Contains(trimmed, "://") {
				fields := strings.Split(trimmed, "|")
				last := strings.TrimSpace(fields[len(fields)-1])
				if strings.Contains(last, "://") {
					urls = append(urls, last)
				}
			}
		default:
			// Real dnf5 `repoinfo` line (verified against a live Fedora container,
			// including a real third-party repo): "  Base URL           : <url>" or
			// "  Base URL           : <url> (27 more)" when the repo has mirrors. Only
			// the first URL is taken either way. dnf4/yum's legacy "repolist -v" wording
			// is not re-verified here.
			if idx := strings.Index(trimmed, "Base URL"); idx == 0 {
				_, value, ok := strings.Cut(trimmed, ":")
				if ok {
					for _, candidate := range strings.Fields(value) {
						if strings.Contains(candidate, "://") {
							urls = append(urls, strings.TrimSuffix(candidate, ","))
							break
						}
					}
				}
			}
		}
	}
	return urls
}
