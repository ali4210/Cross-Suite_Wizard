package playbook

// Unit tests for diagnoseWindowsPackageManagers' finding/action generation, using a fake
// repohealer.Executor instead of a real *ssh.Client — the same injectable-executor pattern
// pkg/repohealer's Homebrew/Emerge adapters use. This function makes exactly one call
// (exec.Run with the diagnostic probe script) and does everything else as pure string
// parsing, so these tests exercise that parsing directly against realistic captured output
// shaped exactly like windowsDiagnosticProbeScript's real Write-Output sections.

import (
	"strings"
	"testing"

	"cross-ssh/pkg/repohealer"
)

type fakeWindowsProbeExecutor struct {
	output string
}

func (f *fakeWindowsProbeExecutor) Run(command string) (string, error) {
	return f.output, nil
}

func (f *fakeWindowsProbeExecutor) RunSudo(script string) (string, error) {
	return f.output, nil
}

func (f *fakeWindowsProbeExecutor) RunSudoWithLabel(script, label string) (string, error) {
	return f.output, nil
}

func hasFindingCode(findings []repohealer.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func hasActionID(actions []windowsPackageFix, id string) bool {
	for _, a := range actions {
		if a.ID == id {
			return true
		}
	}
	return false
}

func TestDiagnoseWindowsPackageManagers(t *testing.T) {
	const healthyExecPolicyAndTLS = "=== EXEC_POLICY ===\nRemoteSigned\n=== TLS ===\nTls12\n"

	cases := []struct {
		name           string
		output         string
		wantFindings   []string
		wantActions    []string
		wantNoFindings bool
	}{
		{
			name: "all healthy",
			output: "=== WINGET ===\nPRESENT\nSource  Argument\n------  --------\nwinget  https://cdn.winget.microsoft.com/cache\n" +
				"=== CHOCO ===\nPRESENT\nchocolatey - https://community.chocolatey.org/api/v2/\nLIB_BAD_COUNT=0\n" +
				"=== SCOOP ===\nPRESENT\nName  Source\n----  ------\nmain  https://github.com/ScoopInstaller/Main\nMAIN_BUCKET_PRESENT\n" +
				healthyExecPolicyAndTLS,
			wantNoFindings: true,
		},
		{
			name:         "winget missing",
			output:       "=== WINGET ===\nMISSING\n=== CHOCO ===\nMISSING\n=== SCOOP ===\nMISSING\n" + healthyExecPolicyAndTLS,
			wantFindings: []string{"WINGET_MISSING", "CHOCOLATEY_MISSING", "SCOOP_MISSING"},
		},
		{
			name: "winget source corrupt",
			output: "=== WINGET ===\nPRESENT\nSOURCE_LIST_ERROR: 0x8a15000f Failed\n" +
				"=== CHOCO ===\nMISSING\n=== SCOOP ===\nMISSING\n" + healthyExecPolicyAndTLS,
			wantFindings: []string{"WINGET_SOURCE_CORRUPT"},
			wantActions:  []string{"winget-source-reset"},
		},
		{
			name: "chocolatey lib-bad present",
			output: "=== WINGET ===\nMISSING\n" +
				"=== CHOCO ===\nPRESENT\nchocolatey - https://community.chocolatey.org/api/v2/\nLIB_BAD_COUNT=3\n" +
				"=== SCOOP ===\nMISSING\n" + healthyExecPolicyAndTLS,
			wantFindings: []string{"CHOCOLATEY_LIB_BAD_PRESENT"},
			wantActions:  []string{"choco-clear-lib-bad"},
		},
		{
			name: "chocolatey source corrupt",
			output: "=== WINGET ===\nMISSING\n" +
				"=== CHOCO ===\nPRESENT\nSOURCE_LIST_ERROR: Unable to connect\nLIB_BAD_COUNT=0\n" +
				"=== SCOOP ===\nMISSING\n" + healthyExecPolicyAndTLS,
			wantFindings: []string{"CHOCOLATEY_SOURCE_CORRUPT"},
			wantActions:  []string{"choco-reset-source"},
		},
		{
			name: "scoop bucket list error",
			output: "=== WINGET ===\nMISSING\n=== CHOCO ===\nMISSING\n" +
				"=== SCOOP ===\nPRESENT\nBUCKET_LIST_ERROR: Could not find a part of the path\n" +
				healthyExecPolicyAndTLS,
			wantFindings: []string{"SCOOP_BUCKET_CORRUPT"},
			wantActions:  []string{"scoop-checkup-update"},
		},
		{
			name: "scoop main bucket missing",
			output: "=== WINGET ===\nMISSING\n=== CHOCO ===\nMISSING\n" +
				"=== SCOOP ===\nPRESENT\nName    Source\n----    ------\nextras  https://github.com/ScoopInstaller/Extras\nMAIN_BUCKET_MISSING\n" +
				healthyExecPolicyAndTLS,
			wantFindings: []string{"SCOOP_MAIN_BUCKET_MISSING"},
			wantActions:  []string{"scoop-add-main-bucket"},
		},
		{
			name: "scoop main bucket present alongside other buckets",
			output: "=== WINGET ===\nPRESENT\nSource  Argument\n------  --------\nwinget  https://cdn.winget.microsoft.com/cache\n" +
				"=== CHOCO ===\nPRESENT\nchocolatey - https://community.chocolatey.org/api/v2/\nLIB_BAD_COUNT=0\n" +
				"=== SCOOP ===\nPRESENT\nName    Source\n----    ------\nmain    https://github.com/ScoopInstaller/Main\nextras  https://github.com/ScoopInstaller/Extras\nMAIN_BUCKET_PRESENT\n" +
				healthyExecPolicyAndTLS,
			wantNoFindings: true,
		},
		{
			name: "execution policy restricted",
			output: "=== WINGET ===\nMISSING\n=== CHOCO ===\nMISSING\n=== SCOOP ===\nMISSING\n" +
				"=== EXEC_POLICY ===\nRestricted\n=== TLS ===\nTls12\n",
			wantFindings: []string{"POWERSHELL_EXECUTION_POLICY_BLOCKING"},
			wantActions:  []string{"powershell-execution-policy-remotesigned"},
		},
		{
			name: "tls12 not active",
			output: "=== WINGET ===\nMISSING\n=== CHOCO ===\nMISSING\n=== SCOOP ===\nMISSING\n" +
				"=== EXEC_POLICY ===\nRemoteSigned\n=== TLS ===\nSsl3, Tls\n",
			wantFindings: []string{"POWERSHELL_TLS12_NOT_ACTIVE"},
			wantActions:  []string{"powershell-enable-tls12"},
		},
		{
			name:         "empty probe output",
			output:       "",
			wantFindings: []string{"WINDOWS_DIAGNOSTIC_INCOMPLETE"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, actions, rawOutput := diagnoseWindowsPackageManagers(&fakeWindowsProbeExecutor{output: c.output})

			if rawOutput != c.output {
				t.Fatalf("expected the raw probe output to be passed through unchanged, got %q want %q", rawOutput, c.output)
			}

			if c.wantNoFindings {
				// "missing tool" / "WINDOWS_DIAGNOSTIC_INCOMPLETE" findings are the only
				// kind this function ever emits for a healthy, fully-present state —
				// neither should fire here.
				for _, f := range findings {
					if strings.Contains(f.Code, "MISSING") || f.Code == "WINDOWS_DIAGNOSTIC_INCOMPLETE" {
						t.Errorf("unexpected finding %s on an all-healthy probe", f.Code)
					}
				}
				if len(actions) != 0 {
					t.Errorf("expected no repair actions on an all-healthy probe, got %v", actions)
				}
				return
			}

			for _, wantCode := range c.wantFindings {
				if !hasFindingCode(findings, wantCode) {
					t.Errorf("expected finding %s, got findings %+v", wantCode, findings)
				}
			}
			for _, wantID := range c.wantActions {
				if !hasActionID(actions, wantID) {
					t.Errorf("expected action %s, got actions %+v", wantID, actions)
				}
			}
		})
	}
}
