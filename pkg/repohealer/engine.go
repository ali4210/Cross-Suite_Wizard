package repohealer

import (
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
)

type Engine struct {
	exec     Executor
	targetOS osdetect.TargetOS
	policy   Policy
}

func New(exec Executor, targetOS osdetect.TargetOS, policy Policy) *Engine {
	return &Engine{
		exec:     exec,
		targetOS: targetOS,
		policy:   policy,
	}
}

func (e *Engine) Run() Result {
	result := Result{
		StartedAt: time.Now().UTC(),
		Mode:      e.policy.Mode,
		Target: TargetFacts{
			Platform:       mapTargetPlatform(e.targetOS),
			PackageManager: ManagerUnknown,
		},
	}

	facts, initialEvidence := e.detectFacts(result.Target.Platform)
	result.Target = facts
	result.Evidence = append(result.Evidence, initialEvidence...)

	switch facts.PackageManager {
	case ManagerAPT:
		adapter := APTAdapter{}
		evidence, findings, actions := adapter.Diagnose(e.exec, facts, e.policy)
		result.Evidence = append(result.Evidence, evidence...)
		result.Findings = append(result.Findings, findings...)
		result.Actions = append(result.Actions, actions...)
	default:
		result.Findings = append(result.Findings, Finding{
			Code:            "PACKAGE_MANAGER_ADAPTER_NOT_IMPLEMENTED",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "A package manager was detected, but its dedicated adapter is not implemented in this first backend milestone.",
			RecommendedFix:  "Run in diagnostic-only mode and implement/test the native adapter before enabling repairs.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	if e.policy.CollectJournal && facts.Platform == PlatformLinux && facts.InitSystem == "systemd" {
		result.Evidence = append(result.Evidence, CollectSystemdJournal(e.exec)...)
	}

	result.Actions = append(result.Actions, BuildRepairPlan(result)...)
	result.VerificationOK = !hasBlockingFindings(result.Findings)
	result.ChangesApplied = false
	result.CompletedAt = time.Now().UTC()
	result.Summary = buildSummary(result)

	return result
}

func (e *Engine) detectFacts(platform Platform) (TargetFacts, []CommandEvidence) {
	facts := TargetFacts{
		Platform:       platform,
		PackageManager: ManagerUnknown,
	}

	command := `
if command -v apt-get >/dev/null 2>&1; then
  echo "manager=apt"
elif command -v dnf >/dev/null 2>&1; then
  echo "manager=dnf"
elif command -v yum >/dev/null 2>&1; then
  echo "manager=yum"
elif command -v zypper >/dev/null 2>&1; then
  echo "manager=zypper"
elif command -v pacman >/dev/null 2>&1; then
  echo "manager=pacman"
elif command -v brew >/dev/null 2>&1; then
  echo "manager=homebrew"
elif command -v winget >/dev/null 2>&1; then
  echo "manager=winget"
elif command -v choco >/dev/null 2>&1; then
  echo "manager=chocolatey"
else
  echo "manager=unknown"
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  echo "distribution=$ID"
  echo "version=$VERSION_ID"
  echo "codename=${VERSION_CODENAME:-}"
fi

uname -m 2>/dev/null | sed 's/^/architecture=/'
ps -p 1 -o comm= 2>/dev/null | sed 's/^/init=/'
`

	started := time.Now()
	output, err := e.exec.Run(command)

	exitCode := 0
	if err != nil {
		exitCode = 1
	}

	evidence := []CommandEvidence{{
		Command:  "detect target platform, operating system, init system, architecture, and package manager",
		Output:   strings.TrimSpace(output),
		ExitCode: exitCode,
		Duration: time.Since(started),
	}}

	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}

		switch key {
		case "manager":
			facts.PackageManager = PackageManager(value)
		case "distribution":
			facts.Distribution = value
		case "version":
			facts.Version = value
		case "codename":
			facts.Codename = value
		case "architecture":
			facts.Architecture = value
		case "init":
			facts.InitSystem = value
		}
	}

	return facts, evidence
}

func mapTargetPlatform(targetOS osdetect.TargetOS) Platform {
	switch targetOS {
	case osdetect.OSWindows:
		return PlatformWindows
	case osdetect.OSMacOS:
		return PlatformMacOS
	default:
		return PlatformLinux
	}
}

func hasBlockingFindings(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity == SeverityError || finding.Severity == SeverityCritical {
			return true
		}
	}

	return false
}

func buildSummary(result Result) string {
	errors := 0
	warnings := 0

	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityError, SeverityCritical:
			errors++
		case SeverityWarning:
			warnings++
		}
	}

	switch {
	case errors > 0:
		return "PARTIAL: diagnostics completed; one or more blocking findings require a controlled repair plan."
	case warnings > 0:
		return "WARNING: diagnostics completed with non-blocking findings."
	default:
		return "PASS: diagnostics completed with no blocking findings."
	}
}
