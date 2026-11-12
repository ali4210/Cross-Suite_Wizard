//go:build darwin

package repohealer

import (
	"os/exec"
	"testing"
)

// localShellExecutor runs commands on the local machine via bash instead of over SSH. It
// satisfies the Executor interface so HomebrewAdapter.Diagnose — which only ever needs
// Run/RunSudo/RunSudoWithLabel, not an actual SSH connection — can be exercised for real
// against a real local Homebrew installation in CI, with no SSH server required.
type localShellExecutor struct{}

func (l localShellExecutor) Run(command string) (string, error) {
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	return string(out), err
}

func (l localShellExecutor) RunSudo(script string) (string, error) {
	return l.Run(script)
}

func (l localShellExecutor) RunSudoWithLabel(script, label string) (string, error) {
	return l.Run(script)
}

// TestHomebrewAdapterDiagnoseReadOnlyOnRealHost runs the real HomebrewAdapter.Diagnose
// against the actual local Homebrew installation on a real macOS host (CI runners ship
// Homebrew preinstalled). brew doctor and brew update are read-only diagnostic commands —
// this never applies any repair action, only exercises the diagnose path.
func TestHomebrewAdapterDiagnoseReadOnlyOnRealHost(t *testing.T) {
	if _, err := exec.LookPath("brew"); err != nil {
		t.Skip("brew not found on PATH")
	}

	executor := localShellExecutor{}
	evidence, _, _ := HomebrewAdapter{}.Diagnose(executor, TargetFacts{Platform: PlatformMacOS, PackageManager: ManagerHomebrew}, DefaultDiagnosticPolicy())

	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence records (brew doctor, brew update), got %d: %+v", len(evidence), evidence)
	}
	for _, e := range evidence {
		if e.Command != "brew doctor 2>&1" && e.Command != "brew update 2>&1" {
			t.Fatalf("unexpected command recorded as evidence: %q", e.Command)
		}
	}
}
