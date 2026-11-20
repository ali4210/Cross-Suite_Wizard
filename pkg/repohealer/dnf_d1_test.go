package repohealer

import (
	"strings"
	"testing"
)

// Regression tests for D1 (real-container dnf verification pass, 2026-11-20): a lock
// probe, a known-vendor configured-key freshness check, and a fix for a real false-positive
// bug in the metadata-stale check — all confirmed against a live Fedora 45 (dnf5)
// container; see dnf.go's comments for the exact captured wording each one is based on.

func TestDNFAdapterDetectsActiveLockFromAnotherProcess(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			// Captured verbatim from a live Fedora 45 container: a concurrent `dnf
			// install -y firefox` held /var/lib/dnf/system-repo.lock while this probe
			// walked /proc/*/fd to find it.
			"DNF_LOCK_ACTIVE|pid=779|cmd=dnf install -y firefox ",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"Metadata cache created.\n",
			"",
		},
	}

	_, findings, _ := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_LOCK_ACTIVE") {
		t.Fatalf("expected DNF_LOCK_ACTIVE finding, got %v", findingCodes(findings))
	}
	for _, f := range findings {
		if f.Code == "DNF_LOCK_ACTIVE" {
			if f.AutoRepairable {
				t.Fatal("an active lock held by another process must never be auto-repairable")
			}
			if !strings.Contains(f.Evidence, "firefox") {
				t.Fatalf("expected evidence to name the owning process, got: %s", f.Evidence)
			}
		}
	}
}

func TestDNFAdapterNoLockFindingWhenAbsent(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"DNF_LOCK_ABSENT",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"Metadata cache created.\n",
			"",
		},
	}

	_, findings, _ := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if containsCode(findingCodes(findings), "DNF_LOCK_ACTIVE") {
		t.Fatalf("did not expect a lock finding when absent, got %v", findingCodes(findings))
	}
}

// TestDNFAdapterHealthyMakecacheNeverFalsePositivesAsStale is a regression test for a real
// bug confirmed live: dnf5 always prints "Metadata cache created." on a completely healthy
// run, and the original check's bare `strings.Contains(lowerCache, "cache")` fallback
// matched that success banner itself, raising DNF_METADATA_STALE on every single run
// regardless of whether anything was actually wrong.
func TestDNFAdapterHealthyMakecacheNeverFalsePositivesAsStale(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"DNF_LOCK_ABSENT",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			" Fedora 45 - x86_64 - Updates           100% | 645.9 KiB/s |   5.7 MiB |  00m09s\nRepositories loaded.\nMetadata cache created.\n",
			"",
		},
	}

	_, findings, actions := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if containsCode(findingCodes(findings), "DNF_METADATA_STALE") {
		t.Fatalf("a healthy makecache run must never be flagged as stale, got %v", findingCodes(findings))
	}
	if len(actions) != 0 {
		t.Fatalf("a healthy run must propose no repair actions, got %+v", actions)
	}
}

// TestDNFAdapterMetadataStaleMatchesRealDNF5ChecksumWording is a regression test using the
// real dnf5 wording captured by corrupting a cached repodata file's checksum reference in a
// live Fedora 45 container: "Failed to download metadata... Error loading local metadata
// for repository... Librepo error: Checksum error ...: Unable to validate zchunk
// checksums" — none of which the pattern this replaced checked for.
func TestDNFAdapterMetadataStaleMatchesRealDNF5ChecksumWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"DNF_LOCK_ABSENT",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"Updating and loading repositories:\n" +
				"Failed to download metadata\n" +
				" Error loading local metadata for repository \"fedora\"\n" +
				"  Librepo error: Checksum error /var/cache/libdnf5/fedora-xyz/repodata/abc-primary.xml.zck: Unable to validate zchunk checksums\n",
			"",
		},
	}

	_, findings, actions := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if !containsCode(findingCodes(findings), "DNF_METADATA_STALE") {
		t.Fatalf("expected DNF_METADATA_STALE for a real checksum-validation failure, got %v", findingCodes(findings))
	}
	if len(actions) != 1 || actions[0].ID != "dnf-stale-cache-clean" {
		t.Fatalf("expected dnf-stale-cache-clean action, got %+v", actions)
	}
}

// TestDNFAdapterDetectsKnownVendorKeySwappedForWrongButReachableKey is a regression test
// for a real detection gap confirmed live: `dnf makecache` alone never reports any error at
// all when a repo's gpgkey= is swapped for a different, reachable vendor's key, as long as
// that repo doesn't sign its own metadata (repo_gpgcheck — true for 16 of this catalog's 17
// RPM vendors). The real failure only ever surfaced at `dnf install` time ("Transaction
// failed: Signature verification failed... Import of the key didn't help, wrong key?"),
// which diagnose must never run. This re-checks the repo's own configured key, read-only,
// against the vendor's pinned fingerprint instead.
func TestDNFAdapterDetectsKnownVendorKeySwappedForWrongButReachableKey(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"DNF_LOCK_ABSENT",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"Metadata cache created.\n", // makecache shows NO error at all
			"[docker-ce-stable]\n" +
				"name=Docker CE Stable\n" +
				"baseurl=https://download.docker.com/linux/fedora/45/x86_64/stable\n" +
				"enabled=1\n" +
				"gpgcheck=1\n" +
				"gpgkey=https://rpm.releases.hashicorp.com/gpg\n", // the WRONG, but reachable, vendor's key
			// configured key's real downloaded fingerprint — HashiCorp's, not Docker's
			"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
		},
	}

	_, findings, _ := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	found := false
	for _, f := range findings {
		if f.Code == "DNF_REPO_GPG_FAILURE" {
			found = true
			if f.Risk != RiskKnownVendor {
				t.Fatalf("expected RiskKnownVendor for a known-vendor key mismatch, got %v", f.Risk)
			}
			if !f.AutoRepairable {
				t.Fatal("a known-vendor key mismatch must route into the gated auto-repair pipeline")
			}
			if !strings.Contains(f.Evidence, "Docker CE") {
				t.Fatalf("expected evidence to name the affected vendor, got: %s", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected DNF_REPO_GPG_FAILURE even though makecache showed no error, got %v", findingCodes(findings))
	}
}

func TestDNFAdapterNoKeyMismatchFindingWhenConfiguredKeyMatchesPinned(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"DNF_LOCK_ABSENT",
			"=== REPOLIST ===\n=== HISTORY ===\n=== RPMDB ===\n",
			"Metadata cache created.\n",
			"[docker-ce-stable]\n" +
				"name=Docker CE Stable\n" +
				"baseurl=https://download.docker.com/linux/fedora/45/x86_64/stable\n" +
				"enabled=1\n" +
				"gpgcheck=1\n" +
				"gpgkey=https://download.docker.com/linux/fedora/gpg\n", // the CORRECT key
			"060A61C51B558A7F742B77AAC52FEB6B621E9F35", // Docker's real, pinned fingerprint
		},
	}

	_, findings, _ := DNFAdapter{BinaryName: "dnf"}.Diagnose(exec, TargetFacts{}, Policy{})

	if containsCode(findingCodes(findings), "DNF_REPO_GPG_FAILURE") {
		t.Fatalf("a correctly-configured known-vendor key must not be flagged, got %v", findingCodes(findings))
	}
}

func TestParseRPMRepoFileBlocksExtractsBaseurlAndGpgkey(t *testing.T) {
	content := `[one]
name=One
baseurl=https://example.invalid/one
gpgkey=https://example.invalid/one/key.asc

[two]
name=Two
baseurl=https://example.invalid/two
# gpgkey is commented out and must be ignored
#gpgkey=https://example.invalid/wrong
`

	blocks := parseRPMRepoFileBlocks(content)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d: %+v", len(blocks), blocks)
	}
	if blocks[0].baseurl != "https://example.invalid/one" || blocks[0].gpgkey != "https://example.invalid/one/key.asc" {
		t.Fatalf("unexpected first block: %+v", blocks[0])
	}
	if blocks[1].baseurl != "https://example.invalid/two" || blocks[1].gpgkey != "" {
		t.Fatalf("unexpected second block (commented gpgkey must not be parsed): %+v", blocks[1])
	}
}

func TestHasAnyFingerprintIsCaseInsensitive(t *testing.T) {
	output := "d55c0d1ac78a8d8126cb631cfc9ca96aca026560\n"
	expected := []string{"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"}

	if !hasAnyFingerprint(output, expected) {
		t.Fatal("expected a case-insensitive fingerprint match")
	}
	if hasAnyFingerprint("", expected) {
		t.Fatal("empty output must never match")
	}
}
