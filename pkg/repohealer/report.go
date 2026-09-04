package repohealer

import (
	"fmt"
	"strings"
)

func RenderTerminal(result Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "\n================================================================================\n")
	fmt.Fprintf(&b, "=== UNIVERSAL REPOSITORY HEALER REPORT                                         ===\n")
	fmt.Fprintf(&b, "================================================================================\n")
	fmt.Fprintf(&b, "Mode: %s\n", result.Mode)
	fmt.Fprintf(&b, "Platform: %s\n", result.Target.Platform)
	fmt.Fprintf(&b, "Distribution: %s %s %s\n", result.Target.Distribution, result.Target.Version, result.Target.Codename)
	fmt.Fprintf(&b, "Architecture: %s\n", result.Target.Architecture)
	fmt.Fprintf(&b, "Init system: %s\n", result.Target.InitSystem)
	fmt.Fprintf(&b, "Package manager: %s\n", result.Target.PackageManager)
	fmt.Fprintf(&b, "Evidence records: %d\n", len(result.Evidence))
	fmt.Fprintf(&b, "Findings: %d\n", len(result.Findings))
	fmt.Fprintf(&b, "Planned repair actions: %d\n", len(result.Actions))
	fmt.Fprintf(&b, "Changes applied: %t\n", result.ChangesApplied)
	fmt.Fprintf(&b, "================================================================================\n\n")

	if len(result.Findings) == 0 {
		b.WriteString("[PASS] No repository findings were detected in diagnostic mode.\n")
	} else {
		for _, finding := range result.Findings {
			fmt.Fprintf(&b, "[%s] %s\n", finding.Severity, finding.Code)

			if finding.RepositoryName != "" {
				fmt.Fprintf(&b, "Repository: %s\n", finding.RepositoryName)
			}
			if finding.RepositoryURL != "" {
				fmt.Fprintf(&b, "Repository URL: %s\n", finding.RepositoryURL)
			}
			if finding.SourceFile != "" {
				fmt.Fprintf(&b, "Source file: %s\n", finding.SourceFile)
			}
			if finding.SourceLine > 0 {
				fmt.Fprintf(&b, "Source line: %d\n", finding.SourceLine)
			}

			fmt.Fprintf(&b, "Evidence: %s\n", finding.Evidence)
			fmt.Fprintf(&b, "Recommended action: %s\n", finding.RecommendedFix)
			fmt.Fprintf(&b, "Risk: %s\n", finding.Risk)
			fmt.Fprintf(&b, "Automatic repair eligible: %t\n", finding.AutoRepairable)
			fmt.Fprintf(&b, "Administrator approval required: %t\n\n", finding.RequiresConsent)
		}
	}

	if len(result.Actions) > 0 {
		b.WriteString("================================================================================\n")
		b.WriteString("=== PLANNED KNOWN-VENDOR REPAIRS — NOT EXECUTED                               ===\n")
		b.WriteString("================================================================================\n\n")

		for index, action := range result.Actions {
			fmt.Fprintf(&b, "[PLAN %d] %s\n", index+1, action.Description)
			fmt.Fprintf(&b, "Risk: %s\n", action.Risk)
			fmt.Fprintf(&b, "Administrator approval required: %t\n", action.RequiresConsent)

			for _, command := range action.Commands {
				fmt.Fprintf(&b, "- %s\n", command)
			}

			fmt.Fprintf(&b, "Verification: %s\n", strings.Join(action.Verification, " | "))
			fmt.Fprintf(&b, "Rollback: %s\n\n", strings.Join(action.Rollback, " | "))
		}
	}

	fmt.Fprintf(&b, "Outcome: %s\n", result.Summary)

	if result.Mode == ModeDiagnose {
		b.WriteString("\n[SAFE MODE] Diagnostic-only mode made no repository, keyring, package, lock, cache, or system configuration changes.\n")
	}

	return b.String()
}
