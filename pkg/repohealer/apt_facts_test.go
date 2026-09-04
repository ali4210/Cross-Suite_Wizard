package repohealer

import (
	"testing"
)

func TestCollectAPTFactsUsesAPTArchitectureAndOSRelease(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"os_id=parrot\nos_id_like=debian\nos_version_id=6.4\nos_codename=lory\napt_architecture=amd64\n",
		},
	}

	fallback := TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "unknown",
		Codename:       "",
		Architecture:   "x86_64",
		PackageManager: ManagerAPT,
	}

	got, evidence := CollectAPTFacts(exec, fallback)

	if evidence.ExitCode != 0 {
		t.Fatalf("unexpected evidence exit code: %d", evidence.ExitCode)
	}
	if got.Distribution != "parrot" {
		t.Fatalf("distribution = %q, want parrot", got.Distribution)
	}
	if got.Version != "6.4" {
		t.Fatalf("version = %q, want 6.4", got.Version)
	}
	if got.Codename != "lory" {
		t.Fatalf("codename = %q, want lory", got.Codename)
	}
	if got.Architecture != "amd64" {
		t.Fatalf("architecture = %q, want amd64", got.Architecture)
	}
}

func TestCollectAPTFactsRetainsFallbackForMissingValues(t *testing.T) {
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"os_id=\nos_id_like=debian\nos_version_id=\nos_codename=\napt_architecture=\n",
		},
	}

	fallback := TargetFacts{
		Platform:       PlatformLinux,
		Distribution:   "debian",
		Version:        "12",
		Codename:       "bookworm",
		Architecture:   "amd64",
		PackageManager: ManagerAPT,
	}

	got, _ := CollectAPTFacts(exec, fallback)

	if got.Distribution != "debian" {
		t.Fatalf("distribution fallback = %q", got.Distribution)
	}
	if got.Version != "12" {
		t.Fatalf("version fallback = %q", got.Version)
	}
	if got.Codename != "bookworm" {
		t.Fatalf("codename fallback = %q", got.Codename)
	}
	if got.Architecture != "amd64" {
		t.Fatalf("architecture fallback = %q", got.Architecture)
	}
}
