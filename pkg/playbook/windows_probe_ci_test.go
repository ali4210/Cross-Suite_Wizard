//go:build windows

package playbook

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWindowsDiagnosticProbeScriptExecutesReadOnly runs the exact production probe script
// (WindowsDiagnosticProbeScript) directly via PowerShell on a real Windows host. This is
// read-only by construction — it only queries Get-Command/source lists/execution policy/
// TLS setting, never writes anything — which is why it is safe to run unattended in CI
// without going through the SSH transport this script normally travels over in production
// (that transport assumes a Git-Bash-based OpenSSH target, which a vanilla CI runner is
// not; this test instead verifies the PowerShell content itself is correct and runs clean
// on a real Windows machine).
func TestWindowsDiagnosticProbeScriptExecutesReadOnly(t *testing.T) {
	shell := "pwsh"
	if _, err := exec.LookPath(shell); err != nil {
		shell = "powershell"
		if _, err := exec.LookPath(shell); err != nil {
			t.Skip("neither pwsh nor powershell found on PATH")
		}
	}

	cmd := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", WindowsDiagnosticProbeScript())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe script failed to execute cleanly: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	for _, marker := range []string{"=== WINGET ===", "=== CHOCO ===", "=== SCOOP ===", "=== EXEC_POLICY ===", "=== TLS ==="} {
		if !strings.Contains(output, marker) {
			t.Fatalf("expected marker %q in probe output, got:\n%s", marker, output)
		}
	}
}

// TestWindowsFixActionScriptsParseCleanly AST-parses (never executes) every fix action's
// PowerShell — several of them are mutating (resetting sources, changing the execution
// policy), so unlike the probe script above, this only confirms they are syntactically
// valid, the same way a `-WhatIf`-less destructive script is checked without running it.
func TestWindowsFixActionScriptsParseCleanly(t *testing.T) {
	shell := "pwsh"
	if _, err := exec.LookPath(shell); err != nil {
		shell = "powershell"
		if _, err := exec.LookPath(shell); err != nil {
			t.Skip("neither pwsh nor powershell found on PATH")
		}
	}

	for i, script := range WindowsFixActionScriptsForCI() {
		script := script
		t.Run("", func(t *testing.T) {
			tmp := t.TempDir() + "\\fix.ps1"
			if err := os.WriteFile(tmp, []byte(script), 0o600); err != nil {
				t.Fatalf("could not write temp script: %v", err)
			}

			cmd := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command",
				"$errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('"+tmp+"', [ref]$null, [ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Error $_.ToString() }; exit 1 } else { Write-Output 'PARSE_OK' }")
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "PARSE_OK") {
				t.Fatalf("fix script #%d failed to parse: %v\nscript:\n%s\noutput:\n%s", i, err, script, out)
			}
		})
	}
}
