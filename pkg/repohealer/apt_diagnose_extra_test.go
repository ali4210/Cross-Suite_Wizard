package repohealer

import "testing"

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
