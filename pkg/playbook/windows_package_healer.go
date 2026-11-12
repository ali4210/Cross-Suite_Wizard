package playbook

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// windowsPackageFix is a self-contained, named PowerShell repair for winget/Chocolatey/Scoop.
// Unlike the Linux/macOS repohealer adapters, these run over a UTF16LE+base64-encoded
// PowerShell command (-EncodedCommand), the same transport this file already uses elsewhere
// for Windows, because repohealer's Executor only knows how to run POSIX bash.
type windowsPackageFix struct {
	ID          string
	Description string
	Script      string
	Verify      string
}

// RunWindowsPackageManagerHealer is the Windows-native counterpart to Option 7's Universal
// Repository Healer. It never goes through the bash-based repohealer engine (that engine's
// diagnostics are plain POSIX shell and do not run against a native Windows SSH target).
func RunWindowsPackageManagerHealer(client *ssh.Client) {
	fmt.Println(Cyan + Bold + "\n[+] Launching Windows Package Manager Self-Healer (winget / Chocolatey / Scoop)..." + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] Diagnose only (no system changes)")
	fmt.Println("  [2] Diagnose and apply a selected fix")
	fmt.Println(Red + "  [0] Return to Hub 5 Menu" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	modeChoice := strings.TrimSpace(transfer.ReadRealtimeInput("Select mode [0-2, default: 1]: "))
	if modeChoice == "" {
		modeChoice = "1"
	}
	if modeChoice == "0" || strings.EqualFold(modeChoice, "q") || strings.EqualFold(modeChoice, "back") {
		fmt.Println(Yellow + "[!] Windows package manager healer canceled. No system changes were made." + Reset)
		return
	}

	findings, actions, rawOutput := diagnoseWindowsPackageManagers(client)

	result := repohealer.Result{
		Mode: repohealer.ModeDiagnose,
		Target: repohealer.TargetFacts{
			Platform: repohealer.PlatformWindows,
		},
		Findings: findings,
	}
	fmt.Println(repohealer.RenderTerminal(result))

	if strings.TrimSpace(rawOutput) != "" {
		fmt.Println(Cyan + "Raw diagnostic output is available below if you need more detail:" + Reset)
		fmt.Println(rawOutput)
	}

	if modeChoice != "2" {
		fmt.Println(Yellow + "[SAFE MODE] No winget/Chocolatey/Scoop source, cache, or policy setting was changed." + Reset)
		return
	}

	if len(actions) == 0 {
		fmt.Println(Yellow + "[!] No auto-repairable fix was identified. Review the findings above for manual guidance." + Reset)
		return
	}

	fmt.Println(Cyan + Bold + "\nAvailable fixes:" + Reset)
	for i, fix := range actions {
		fmt.Printf("  [%d] %s\n", i+1, fix.Description)
	}

	selection := strings.TrimSpace(transfer.ReadRealtimeInput(fmt.Sprintf("Select a fix [1-%d] or 0 to cancel: ", len(actions))))
	idx := 0
	if _, err := fmt.Sscanf(selection, "%d", &idx); err != nil || idx < 1 || idx > len(actions) {
		fmt.Println(Yellow + "[!] Invalid selection. No system changes were made." + Reset)
		return
	}
	selected := actions[idx-1]

	fmt.Println(Red + Bold + "\n[!] APPLY MODE: This will run:" + Reset)
	fmt.Println(Yellow + selected.Script + Reset)
	fmt.Println(Yellow + "[!] Note: there is no file-based snapshot for winget/Chocolatey/Scoop state yet, so Option [9] Rollback does not cover this change." + Reset)

	confirmation := strings.TrimSpace(transfer.ReadRealtimeInput("Type yes to apply this exact fix, or anything else to cancel: "))
	applied := false
	var applyOutput string
	if strings.EqualFold(confirmation, "yes") {
		applyOutput = runWindowsPowerShell(client, selected.Script+"\nWrite-Output 'WINDOWS_FIX_DONE'", "Applying: "+selected.Description)
		applied = strings.Contains(applyOutput, "WINDOWS_FIX_DONE")

		if applied && selected.Verify != "" {
			verifyOutput := runWindowsPowerShell(client, selected.Verify, "Verifying fix: "+selected.Description)
			fmt.Println(Cyan + "Verification output:" + Reset)
			fmt.Println(verifyOutput)
		}

		if applied {
			fmt.Println(Green + Bold + "[SUCCESS] " + selected.Description + " applied." + Reset)
		} else {
			fmt.Println(Red + Bold + "[!] Fix did not report completion — review the output above." + Reset)
		}
	} else {
		fmt.Println(Yellow + "[!] Fix cancelled. No system changes were made." + Reset)
	}

	decision := repohealer.ApprovalExecutionExecuted
	if !strings.EqualFold(confirmation, "yes") {
		decision = repohealer.ApprovalExecutionDeclined
	}
	failure := repohealer.RepairFailureNone
	if strings.EqualFold(confirmation, "yes") && !applied {
		failure = repohealer.RepairFailureExecution
	}

	audit := repohealer.RepairAuditEvent{
		Event:           "windows_package_manager_repair",
		OccurredAt:      time.Now().UTC(),
		Decision:        decision,
		ActionID:        selected.ID,
		RepairAttempted: strings.EqualFold(confirmation, "yes"),
		Applied:         applied,
		FailureCategory: failure,
	}
	auditPath := repohealer.RepairAuditPath()
	if err := repohealer.AppendRepairAuditEvent(auditPath, audit); err != nil {
		fmt.Println(Yellow + fmt.Sprintf("WARNING: audit event could not be persisted to %q: %v", auditPath, err) + Reset)
	} else {
		fmt.Println(Cyan + fmt.Sprintf("Audit record written: %s", auditPath) + Reset)
	}
}

// diagnoseWindowsPackageManagers runs a single read-only PowerShell probe covering winget,
// Chocolatey, Scoop, the PowerShell execution policy, and the TLS 1.2 setting, then turns
// anything suspicious into findings and candidate fixes.
func diagnoseWindowsPackageManagers(client *ssh.Client) ([]repohealer.Finding, []windowsPackageFix, string) {
	const probe = `
Write-Output '=== WINGET ==='
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Output 'PRESENT'
    try { winget source list 2>&1 } catch { Write-Output "SOURCE_LIST_ERROR: $($_.Exception.Message)" }
} else {
    Write-Output 'MISSING'
}

Write-Output '=== CHOCO ==='
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Output 'PRESENT'
    try { choco source list 2>&1 } catch { Write-Output "SOURCE_LIST_ERROR: $($_.Exception.Message)" }
    if ($env:ChocolateyInstall -and (Test-Path "$env:ChocolateyInstall\lib-bad")) {
        $badCount = (Get-ChildItem "$env:ChocolateyInstall\lib-bad" -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Output "LIB_BAD_COUNT=$badCount"
    } else {
        Write-Output "LIB_BAD_COUNT=0"
    }
} else {
    Write-Output 'MISSING'
}

Write-Output '=== SCOOP ==='
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Output 'PRESENT'
    try { scoop bucket list 2>&1 } catch { Write-Output "BUCKET_LIST_ERROR: $($_.Exception.Message)" }
} else {
    Write-Output 'MISSING'
}

Write-Output '=== EXEC_POLICY ==='
(Get-ExecutionPolicy -Scope CurrentUser)

Write-Output '=== TLS ==='
([System.Net.ServicePointManager]::SecurityProtocol)
`
	output := runWindowsPowerShell(client, probe, "Diagnosing Windows Package Managers")
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	sections := splitWindowsFactSections(normalized)

	var findings []repohealer.Finding
	var actions []windowsPackageFix

	winget := sections["WINGET"]
	if strings.Contains(winget, "MISSING") {
		findings = append(findings, repohealer.Finding{
			Code:            "WINGET_MISSING",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskManual,
			Evidence:        "winget is not installed or not on PATH.",
			RecommendedFix:  "Use Hub 5 Option [5] (Windows Package Manager Setup) to install the App Installer bundle.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	} else if strings.Contains(winget, "SOURCE_LIST_ERROR") || strings.Contains(strings.ToLower(winget), "failed") {
		findings = append(findings, repohealer.Finding{
			Code:            "WINGET_SOURCE_CORRUPT",
			Severity:        repohealer.SeverityError,
			Risk:            repohealer.RiskAutoSafe,
			Evidence:        "winget source list reported an error, which usually means a corrupted local source index.",
			RecommendedFix:  "Reset winget's package sources (winget source reset --force).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, windowsPackageFix{
			ID:          "winget-source-reset",
			Description: "Reset winget package sources",
			Script:      "winget source reset --force",
			Verify:      "winget source list",
		})
	}

	choco := sections["CHOCO"]
	if strings.Contains(choco, "MISSING") {
		findings = append(findings, repohealer.Finding{
			Code:            "CHOCOLATEY_MISSING",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskManual,
			Evidence:        "Chocolatey is not installed or not on PATH.",
			RecommendedFix:  "Use Hub 5 Option [5] (Windows Package Manager Setup) to install Chocolatey.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	} else {
		if strings.Contains(choco, "LIB_BAD_COUNT=") && !strings.Contains(choco, "LIB_BAD_COUNT=0") {
			findings = append(findings, repohealer.Finding{
				Code:            "CHOCOLATEY_LIB_BAD_PRESENT",
				Severity:        repohealer.SeverityWarning,
				Risk:            repohealer.RiskAutoSafe,
				Evidence:        "Chocolatey's lib-bad directory contains leftovers from failed installs, which can block future installs of the same package.",
				RecommendedFix:  "Clear $env:ChocolateyInstall\\lib-bad after confirming no install is in progress.",
				AutoRepairable:  true,
				RequiresConsent: true,
			})
			actions = append(actions, windowsPackageFix{
				ID:          "choco-clear-lib-bad",
				Description: "Clear Chocolatey's lib-bad (failed install) directory",
				Script:      `Remove-Item -Path "$env:ChocolateyInstall\lib-bad\*" -Recurse -Force -ErrorAction SilentlyContinue`,
				Verify:      `Get-ChildItem "$env:ChocolateyInstall\lib-bad" -ErrorAction SilentlyContinue | Measure-Object`,
			})
		}
		if strings.Contains(choco, "SOURCE_LIST_ERROR") {
			findings = append(findings, repohealer.Finding{
				Code:            "CHOCOLATEY_SOURCE_CORRUPT",
				Severity:        repohealer.SeverityError,
				Risk:            repohealer.RiskApprovalNeeded,
				Evidence:        "choco source list reported an error.",
				RecommendedFix:  "Remove and re-add the default community source (choco source remove -n=chocolatey; choco source add -n=chocolatey -s https://community.chocolatey.org/api/v2/).",
				AutoRepairable:  true,
				RequiresConsent: true,
			})
			actions = append(actions, windowsPackageFix{
				ID:          "choco-reset-source",
				Description: "Reset Chocolatey's default community source",
				Script:      "choco source remove -n=chocolatey 2>$null; choco source add -n=chocolatey -s https://community.chocolatey.org/api/v2/",
				Verify:      "choco source list",
			})
		}
	}

	scoop := sections["SCOOP"]
	if strings.Contains(scoop, "MISSING") {
		findings = append(findings, repohealer.Finding{
			Code:            "SCOOP_MISSING",
			Severity:        repohealer.SeverityInfo,
			Risk:            repohealer.RiskManual,
			Evidence:        "Scoop is not installed or not on PATH.",
			RecommendedFix:  "Scoop is optional; install it manually (iwr -useb get.scoop.sh | iex) as a non-admin user if you want it.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	} else if strings.Contains(scoop, "BUCKET_LIST_ERROR") {
		findings = append(findings, repohealer.Finding{
			Code:            "SCOOP_BUCKET_CORRUPT",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskAutoSafe,
			Evidence:        "scoop bucket list reported an error.",
			RecommendedFix:  "Run `scoop checkup` and `scoop update` to repair bucket/cache state.",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, windowsPackageFix{
			ID:          "scoop-checkup-update",
			Description: "Run scoop checkup and update",
			Script:      "scoop checkup; scoop update",
			Verify:      "scoop bucket list",
		})
	}

	execPolicy := strings.TrimSpace(sections["EXEC_POLICY"])
	if strings.EqualFold(execPolicy, "Restricted") || strings.EqualFold(execPolicy, "AllSigned") {
		findings = append(findings, repohealer.Finding{
			Code:            "POWERSHELL_EXECUTION_POLICY_BLOCKING",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskApprovalNeeded,
			Evidence:        fmt.Sprintf("The CurrentUser PowerShell execution policy is %q, which blocks many package-manager install scripts.", execPolicy),
			RecommendedFix:  "Only if you understand the risk: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force.",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, windowsPackageFix{
			ID:          "powershell-execution-policy-remotesigned",
			Description: "Set CurrentUser PowerShell execution policy to RemoteSigned",
			Script:      "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force",
			Verify:      "Get-ExecutionPolicy -Scope CurrentUser",
		})
	}

	tls := strings.TrimSpace(sections["TLS"])
	if tls != "" && !strings.Contains(tls, "Tls12") && !strings.Contains(tls, "SystemDefault") {
		findings = append(findings, repohealer.Finding{
			Code:            "POWERSHELL_TLS12_NOT_ACTIVE",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskAutoSafe,
			Evidence:        fmt.Sprintf("The current PowerShell session's SecurityProtocol is %q, without TLS 1.2 — many package manager downloads will fail TLS negotiation.", tls),
			RecommendedFix:  "Enable TLS 1.2 for this session ([System.Net.ServicePointManager]::SecurityProtocol = ...Tls12).",
			AutoRepairable:  true,
			RequiresConsent: true,
		})
		actions = append(actions, windowsPackageFix{
			ID:          "powershell-enable-tls12",
			Description: "Enable TLS 1.2 for the current PowerShell session",
			Script:      "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072",
			Verify:      "[System.Net.ServicePointManager]::SecurityProtocol",
		})
	}

	if strings.TrimSpace(output) == "" {
		findings = append(findings, repohealer.Finding{
			Code:            "WINDOWS_DIAGNOSTIC_INCOMPLETE",
			Severity:        repohealer.SeverityWarning,
			Risk:            repohealer.RiskManual,
			Evidence:        "The remote PowerShell probe returned no output; remote command execution may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and PowerShell availability on the target, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	return findings, actions, output
}

func splitWindowsFactSections(output string) map[string]string {
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

// runWindowsPowerShell sends a PowerShell script to the target over SSH using the same
// UTF16LE+base64 -EncodedCommand transport already used elsewhere in this file for Windows.
func runWindowsPowerShell(client *ssh.Client, script string, label string) string {
	utf16LE := make([]byte, 0, len(script)*2)
	for _, r := range script {
		utf16LE = append(utf16LE, byte(r), byte(r>>8))
	}
	b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)
	winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
	out, _ := runSudoScriptWithSpinner(client, winCmd, label)
	return out
}
