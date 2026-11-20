package repohealer

import (
	"fmt"
	"strings"
)

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

// rpmConfiguredKeyScript is a read-only probe: it downloads the exact URL a repo is
// currently configured to trust (never the catalog's own pinned KeyURL) and prints every
// fingerprint found in it, one per line. It makes no change to the target — no `rpm
// --import`, nothing written to disk — mirroring the same read-only intent as every other
// diagnose probe in this file.
func rpmConfiguredKeyScript(keyURL string) string {
	return fmt.Sprintf(`
set +e
curl -fsSL --proto '=https' --tlsv1.2 %q 2>/dev/null \
	| gpg --show-keys --with-colons --with-fingerprint 2>/dev/null \
	| awk -F: '$1 == "fpr" {print toupper($10)}'
`, keyURL)
}

// hasAnyFingerprint reports whether output (one fingerprint per line, as
// rpmConfiguredKeyScript prints) contains any fingerprint from expected.
func hasAnyFingerprint(output string, expected []string) bool {
	found := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		if fp := strings.ToUpper(strings.TrimSpace(line)); fp != "" {
			found[fp] = true
		}
	}
	for _, fp := range expected {
		if found[strings.ToUpper(strings.TrimSpace(fp))] {
			return true
		}
	}
	return false
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

// rpmRepoFileBlock is one [section] parsed directly out of a raw .repo file — the same
// INI-style format both dnf's /etc/yum.repos.d and zypper's /etc/zypp/repos.d use, which is
// exactly why one VendorProfile catalog already serves both.
type rpmRepoFileBlock struct {
	baseurl string
	gpgkey  string
}

// parseRPMRepoFileBlocks parses baseurl=/gpgkey= pairs directly out of raw, concatenated
// .repo file content (e.g. `cat /etc/yum.repos.d/*.repo`).
func parseRPMRepoFileBlocks(content string) []rpmRepoFileBlock {
	var blocks []rpmRepoFileBlock
	var current *rpmRepoFileBlock

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			blocks = append(blocks, rpmRepoFileBlock{})
			current = &blocks[len(blocks)-1]
			continue
		}
		if current == nil {
			continue
		}

		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}

		switch strings.TrimSpace(key) {
		case "baseurl":
			current.baseurl = strings.TrimSpace(value)
		case "gpgkey":
			// gpgkey may list several space/newline-separated URLs (packagecloud's
			// generated repos do this); only the first is checked.
			if fields := strings.Fields(value); len(fields) > 0 {
				current.gpgkey = fields[0]
			}
		}
	}

	return blocks
}

// discoverKnownRPMVendorConfiguredKeyURL returns the ACTUALLY-CONFIGURED gpgkey= value
// (not the pinned catalog KeyURL) for the first repo, parsed from raw .repo file content,
// whose baseurl matches a known vendor profile — closing a real detection gap found while
// reproducing D1(a) in a live Fedora container: `dnf makecache`/`zypper refresh` alone
// cannot surface a key swapped for a wrong-but-reachable one on any vendor that does not
// sign its own repo metadata with repo_gpgcheck (confirmed true for 16 of this catalog's 17
// RPM vendors — only Microsoft's generic repo signs metadata at all). The wrong-key failure
// only ever surfaced for real at `dnf install` time ("Transaction failed: Signature
// verification failed... Import of the key didn't help, wrong key?"), which diagnose must
// never run. Reading the repo's own configured gpgkey= and re-checking its fingerprint,
// read-only, is what actually catches this before an operator hits it during a real
// install.
func discoverKnownRPMVendorConfiguredKeyURL(manager PackageManager, repoFilesContent string) (VendorProfile, string, bool) {
	for _, block := range parseRPMRepoFileBlocks(repoFilesContent) {
		if block.baseurl == "" {
			continue
		}
		if profile, ok := FindVendorProfile(canonicalRPMManager(manager), block.baseurl); ok {
			return profile, block.gpgkey, true
		}
	}
	return VendorProfile{}, "", false
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
