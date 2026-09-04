package repohealer

import "time"

type Mode string

const (
	ModeDiagnose Mode = "diagnose"
	ModeApply    Mode = "apply"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

type RiskLevel string

const (
	RiskAutoSafe       RiskLevel = "AUTO_SAFE"
	RiskKnownVendor    RiskLevel = "AUTO_KNOWN_VENDOR"
	RiskApprovalNeeded RiskLevel = "APPROVAL_REQUIRED"
	RiskManual         RiskLevel = "MANUAL_REQUIRED"
	RiskBlocked        RiskLevel = "BLOCKED"
)

type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "darwin"
	PlatformWindows Platform = "windows"
)

type PackageManager string

const (
	ManagerAPT        PackageManager = "apt"
	ManagerDNF        PackageManager = "dnf"
	ManagerYUM        PackageManager = "yum"
	ManagerZypper     PackageManager = "zypper"
	ManagerPacman     PackageManager = "pacman"
	ManagerHomebrew   PackageManager = "homebrew"
	ManagerWinget     PackageManager = "winget"
	ManagerChocolatey PackageManager = "chocolatey"
	ManagerUnknown    PackageManager = "unknown"
)

type TargetFacts struct {
	Platform       Platform       `json:"platform"`
	Distribution   string         `json:"distribution,omitempty"`
	Version        string         `json:"version,omitempty"`
	Codename       string         `json:"codename,omitempty"`
	Architecture   string         `json:"architecture,omitempty"`
	InitSystem     string         `json:"init_system,omitempty"`
	PackageManager PackageManager `json:"package_manager"`
}

type CommandEvidence struct {
	Command  string        `json:"command"`
	Output   string        `json:"output"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

type Finding struct {
	Code            string    `json:"code"`
	Severity        Severity  `json:"severity"`
	Risk            RiskLevel `json:"risk"`
	RepositoryName  string    `json:"repository_name,omitempty"`
	RepositoryURL   string    `json:"repository_url,omitempty"`
	SourceFile      string    `json:"source_file,omitempty"`
	SourceLine      int       `json:"source_line,omitempty"`
	Evidence        string    `json:"evidence"`
	RecommendedFix  string    `json:"recommended_fix"`
	AutoRepairable  bool      `json:"auto_repairable"`
	RequiresConsent bool      `json:"requires_consent"`
}

type RepairAction struct {
	ID              string    `json:"id"`
	FindingCode     string    `json:"finding_code"`
	Risk            RiskLevel `json:"risk"`
	Description     string    `json:"description"`
	Commands        []string  `json:"commands"`
	Verification    []string  `json:"verification"`
	Rollback        []string  `json:"rollback"`
	RequiresConsent bool      `json:"requires_consent"`
}

type Snapshot struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	Created   bool      `json:"created"`
}

type Result struct {
	StartedAt      time.Time         `json:"started_at"`
	CompletedAt    time.Time         `json:"completed_at"`
	Mode           Mode              `json:"mode"`
	Target         TargetFacts       `json:"target"`
	Snapshot       Snapshot          `json:"snapshot"`
	Evidence       []CommandEvidence `json:"evidence"`
	Findings       []Finding         `json:"findings"`
	Actions        []RepairAction    `json:"actions"`
	VerificationOK bool              `json:"verification_ok"`
	ChangesApplied bool              `json:"changes_applied"`
	Summary        string            `json:"summary"`
}
