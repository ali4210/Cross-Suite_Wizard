package repohealer

import (
	"strings"
	"testing"
)

func TestAPTAdapterDiagnoseFindsExpiredKey(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\n=== HELD_PACKAGES ===\n",
			"W: An error occurred during the signature verification. EXPKEYSIG 1397BC53640DB551 Example Repo\n",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	if !containsCode(findingCodes(findings), "APT_REPO_KEY_EXPIRED") {
		t.Fatalf("expected APT_REPO_KEY_EXPIRED finding, got %v", findingCodes(findings))
	}
}

// Regression test using the exact output captured from a live Debian 12 container: a repo
// signed with a key that was valid at signing time but has since expired. This confirms
// the EXPKEYSIG pattern (unlike several other patterns in this codebase) already matched
// real apt wording correctly on the first try.
func TestAPTAdapterDiagnoseFindsExpiredKeyRealWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\n=== HELD_PACKAGES ===\n",
			"Get:1 http://localhost:8000 stable InRelease [1456 B]\n" +
				"Err:1 http://localhost:8000 stable InRelease\n" +
				"  The following signatures were invalid: EXPKEYSIG AFADA0F6F5611105 Test Expiring Key <test@example.invalid>\n" +
				"Reading package lists...\n" +
				"W: GPG error: http://localhost:8000 stable InRelease: The following signatures were invalid: EXPKEYSIG AFADA0F6F5611105 Test Expiring Key <test@example.invalid>\n" +
				"E: The repository 'http://localhost:8000 stable InRelease' is not signed.\n",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	if !containsCode(findingCodes(findings), "APT_REPO_KEY_EXPIRED") {
		t.Fatalf("expected APT_REPO_KEY_EXPIRED finding, got %v", findingCodes(findings))
	}
}

func TestAPTAdapterDiagnoseFindsCorruptListsCache(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\n=== HELD_PACKAGES ===\n",
			"Hash Sum mismatch\nSome index files failed to download\n",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	if !containsCode(findingCodes(findings), "APT_LISTS_CACHE_CORRUPT") {
		t.Fatalf("expected APT_LISTS_CACHE_CORRUPT finding, got %v", findingCodes(findings))
	}
}

// Regression test for modern apt's real wording, confirmed against a live Debian 12
// (apt 2.6) container: a deliberately corrupted index on an HTTP-served local repo
// produces "File has unexpected size (N != M). Mirror sync in progress?" — not the
// classic "Hash Sum mismatch" string the original pattern only checked for.
func TestAPTAdapterDiagnoseFindsModernSizeMismatchWording(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\n=== HELD_PACKAGES ===\n",
			"E: Failed to fetch http://localhost:8000/dists/stable/main/binary-amd64/Packages  File has unexpected size (105 != 85). Mirror sync in progress? [IP: 127.0.0.1 8000]\n" +
				"E: Some index files failed to download. They have been ignored, or old ones used instead.\n",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	if !containsCode(findingCodes(findings), "APT_LISTS_CACHE_CORRUPT") {
		t.Fatalf("expected APT_LISTS_CACHE_CORRUPT finding, got %v", findingCodes(findings))
	}
}

func TestAPTAdapterDiagnoseFindsRepo404(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\n=== HELD_PACKAGES ===\n",
			"Err:3 http://archive.example.com/debian bookworm/main amd64 Packages\n  404  Not Found [IP: 10.0.0.1 80]\n",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	if !containsCode(findingCodes(findings), "APT_REPO_404") {
		t.Fatalf("expected APT_REPO_404 finding, got %v", findingCodes(findings))
	}
}

func TestAPTAdapterDiagnoseFindsBrokenAndHeldPackages(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"=== APT_SOURCES ===\n=== SIGNED_BY_REFERENCES ===\n=== KEYRINGS ===\n=== DPKG_AUDIT ===\nfoo is missing files\nbar is half-installed\n=== HELD_PACKAGES ===\nlinux-image-amd64\n",
			"",
		},
	}

	_, findings, _ := APTAdapter{}.Diagnose(
		exec,
		TargetFacts{Platform: PlatformLinux, PackageManager: ManagerAPT},
		DefaultDiagnosticPolicy(),
	)

	codes := findingCodes(findings)
	if !containsCode(codes, "APT_PACKAGES_BROKEN") {
		t.Fatalf("expected APT_PACKAGES_BROKEN finding, got %v", codes)
	}
	if !containsCode(codes, "APT_PACKAGES_HELD") {
		t.Fatalf("expected APT_PACKAGES_HELD finding, got %v", codes)
	}

	var broken, held Finding
	for _, finding := range findings {
		switch finding.Code {
		case "APT_PACKAGES_BROKEN":
			broken = finding
		case "APT_PACKAGES_HELD":
			held = finding
		}
	}

	for _, want := range []string{"foo is missing files", "bar is half-installed"} {
		if !strings.Contains(broken.Evidence, want) {
			t.Fatalf("APT_PACKAGES_BROKEN evidence missing real dpkg --audit line %q, got: %s", want, broken.Evidence)
		}
	}
	if !strings.Contains(broken.RecommendedFix, "apt --fix-broken install") {
		t.Fatalf("APT_PACKAGES_BROKEN fix must name the exact command, got: %s", broken.RecommendedFix)
	}

	if !strings.Contains(held.Evidence, "linux-image-amd64") {
		t.Fatalf("APT_PACKAGES_HELD evidence missing real apt-mark showhold line, got: %s", held.Evidence)
	}
	if !strings.Contains(held.RecommendedFix, "apt-mark unhold") {
		t.Fatalf("APT_PACKAGES_HELD fix must name the exact command, got: %s", held.RecommendedFix)
	}
}

func TestCountAPTInventorySectionLines(t *testing.T) {
	inventory := "=== A ===\nfoo\nbar\n=== B ===\nbaz\n"

	if got := countAPTInventorySectionLines(inventory, "A"); got != 2 {
		t.Fatalf("section A count = %d, want 2", got)
	}
	if got := countAPTInventorySectionLines(inventory, "B"); got != 1 {
		t.Fatalf("section B count = %d, want 1", got)
	}
	if got := countAPTInventorySectionLines(inventory, "MISSING"); got != 0 {
		t.Fatalf("missing section count = %d, want 0", got)
	}
}
