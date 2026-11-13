package repohealer

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Dpkg's own package database; snapshotting both lets a failed "apt --fix-broken install" be
// rolled back to the exact pre-repair package state.
var aptFixBrokenSnapshotTargets = []string{
	"/var/lib/dpkg/status",
	"/var/lib/dpkg/status-old",
}

const aptFixBrokenRepairConfirmation = "FIX BROKEN PACKAGES"

// APTFixBrokenPreview is a read-only, no-system-change look at what "apt --fix-broken install"
// would do right now: the actual dpkg --audit output (so the operator sees exactly what is
// broken) and the exact simulated ("apt-get -s --fix-broken install") change plan.
type APTFixBrokenPreview struct {
	Ready           bool
	Reason          string
	DpkgAuditOutput string
	SimulatedPlan   string
	NothingToRepair bool
}

// BuildAPTFixBrokenPreview runs only read-only commands: dpkg --audit (to show the real broken
// package list) and apt-get's -s (simulate / dry-run) flag for --fix-broken install, which never
// changes the system.
func BuildAPTFixBrokenPreview(exec Executor) (APTFixBrokenPreview, error) {
	auditOutput, err := exec.RunSudo("set +e\ndpkg --audit 2>&1\n")
	if err != nil {
		return APTFixBrokenPreview{}, fmt.Errorf(
			"APT fix-broken preview blocked: dpkg --audit probe failed: %w",
			err,
		)
	}

	auditOutput = strings.TrimSpace(auditOutput)
	if auditOutput == "" {
		return APTFixBrokenPreview{
			Ready:           false,
			NothingToRepair: true,
			Reason:          "dpkg --audit reports no broken or inconsistent packages; there is nothing to repair",
		}, nil
	}

	simulated, err := exec.RunSudoWithLabel(
		"set +e\nexport DEBIAN_FRONTEND=noninteractive\napt-get -s --fix-broken install 2>&1\n",
		"Simulating apt --fix-broken install (dry run, no system changes)",
	)
	if err != nil {
		return APTFixBrokenPreview{}, fmt.Errorf(
			"APT fix-broken preview blocked: apt-get -s --fix-broken install simulation failed: %w",
			err,
		)
	}

	return APTFixBrokenPreview{
		Ready:           true,
		DpkgAuditOutput: auditOutput,
		SimulatedPlan:   strings.TrimSpace(simulated),
	}, nil
}

// APTFixBrokenApplyResult mirrors the other gated-repair apply results in this package.
type APTFixBrokenApplyResult struct {
	Attempted       bool
	Applied         bool
	RolledBack      bool
	Snapshot        Snapshot
	Output          string
	DpkgAuditAfter  string
	VerificationOut string
	Error           error
}

// ApplyAPTFixBrokenRepair snapshots dpkg's package database first, runs
// "apt --fix-broken install -y", then verifies dpkg --audit is now clean and apt-get update
// still works, rolling back automatically on any failure. It never unholds a package itself —
// apt --fix-broken install does not touch apt-mark holds.
func ApplyAPTFixBrokenRepair(exec Executor, preview APTFixBrokenPreview) APTFixBrokenApplyResult {
	result := APTFixBrokenApplyResult{Attempted: true}

	if !preview.Ready {
		result.Error = fmt.Errorf(
			"APT fix-broken repair blocked: preview is not ready: %s",
			strings.TrimSpace(preview.Reason),
		)
		return result
	}

	if err := ensureAPTRepairUnlocked(exec); err != nil {
		result.Error = err
		return result
	}

	snapshot, err := CreateAPTFileSnapshot(exec, aptFixBrokenSnapshotTargets)
	if err != nil {
		result.Error = fmt.Errorf(
			"APT fix-broken repair blocked: could not create targeted dpkg-database snapshot: %w",
			err,
		)
		return result
	}
	result.Snapshot = snapshot

	output, err := exec.RunSudoWithLabel(
		"set +e\nexport DEBIAN_FRONTEND=noninteractive\napt-get -y --fix-broken install 2>&1\nexit ${PIPESTATUS[0]}\n",
		"Running apt --fix-broken install",
	)
	result.Output = strings.TrimSpace(output)
	if err != nil {
		result.Error = fmt.Errorf("apt --fix-broken install failed: %w: %s", err, result.Output)
		rollbackAPTFixBrokenRepair(exec, &result)
		return result
	}

	auditAfter, auditErr := exec.RunSudoWithLabel(
		"set +e\ndpkg --audit 2>&1\n",
		"Verifying dpkg --audit Is Clean",
	)
	result.DpkgAuditAfter = strings.TrimSpace(auditAfter)
	if auditErr != nil || result.DpkgAuditAfter != "" {
		result.Error = fmt.Errorf(
			"apt --fix-broken install ran, but dpkg --audit still reports broken packages: %s",
			result.DpkgAuditAfter,
		)
		rollbackAPTFixBrokenRepair(exec, &result)
		return result
	}

	verificationOut, verifyErr := exec.RunSudoWithLabel(
		defaultAPTVerificationScript,
		"Verifying APT Repository Health",
	)
	result.VerificationOut = strings.TrimSpace(verificationOut)
	if verifyErr != nil {
		result.Error = fmt.Errorf("post-repair apt-get update failed: %w", verifyErr)
		rollbackAPTFixBrokenRepair(exec, &result)
		return result
	}

	result.Applied = true
	return result
}

func rollbackAPTFixBrokenRepair(exec Executor, result *APTFixBrokenApplyResult) {
	rollbackErr := RestoreAPTFileSnapshot(exec, result.Snapshot, aptFixBrokenSnapshotTargets)
	result.RolledBack = rollbackErr == nil

	if rollbackErr != nil {
		result.Error = fmt.Errorf(
			"%w; targeted dpkg-database rollback also failed: %v",
			result.Error,
			rollbackErr,
		)
	}
}

type APTFixBrokenApprovalStatus string

const (
	APTFixBrokenApprovalStatusBlocked  APTFixBrokenApprovalStatus = "blocked"
	APTFixBrokenApprovalStatusDeclined APTFixBrokenApprovalStatus = "declined"
	APTFixBrokenApprovalStatusApplied  APTFixBrokenApprovalStatus = "applied"
	APTFixBrokenApprovalStatusFailed   APTFixBrokenApprovalStatus = "failed"
)

type APTFixBrokenApprovalResult struct {
	Status      APTFixBrokenApprovalStatus
	ApplyResult APTFixBrokenApplyResult
	Reason      string
}

// APTFixBrokenRepairExecutionEnabledEnv is the operator-policy environment variable that must
// be set to exactly "true" before the apt --fix-broken install repair is allowed to apply.
// Exported so callers (e.g. the playbook UI) can show the exact variable name without
// duplicating the string literal.
const APTFixBrokenRepairExecutionEnabledEnv = "CROSS_SUITE_FIXBROKEN_REPAIR_ENABLED"

// APTFixBrokenRepairExecutionEnabled is the same kind of operator-policy opt-in every other
// gated repair in this package requires.
func APTFixBrokenRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(APTFixBrokenRepairExecutionEnabledEnv)),
		"true",
	)
}

// ApproveAndApplyAPTFixBrokenRepair is the single gated entry point for actually running
// "apt --fix-broken install": it requires a ready preview, the exact typed confirmation phrase
// (not a bare "yes", since this can install/remove/downgrade packages system-wide), and the
// operator-policy env flag, plus the same low-disk-space/clock-skew/dpkg-health safety gate
// used by the other gated repairs.
func ApproveAndApplyAPTFixBrokenRepair(
	exec Executor,
	preview APTFixBrokenPreview,
	confirmation string,
) APTFixBrokenApprovalResult {
	result := APTFixBrokenApprovalResult{Status: APTFixBrokenApprovalStatusBlocked}

	if !preview.Ready {
		result.Reason = fmt.Sprintf(
			"APT fix-broken repair approval blocked: preview is not ready: %s",
			strings.TrimSpace(preview.Reason),
		)
		return result
	}

	if strings.TrimSpace(confirmation) != aptFixBrokenRepairConfirmation {
		result.Status = APTFixBrokenApprovalStatusDeclined
		result.Reason = fmt.Sprintf(
			"APT fix-broken repair was not approved: exact confirmation %q is required",
			aptFixBrokenRepairConfirmation,
		)
		return result
	}

	if !APTFixBrokenRepairExecutionEnabled() {
		result.Reason = "APT fix-broken repair execution is disabled by operator policy; " +
			"set CROSS_SUITE_FIXBROKEN_REPAIR_ENABLED=true only for approved maintenance"
		return result
	}

	// BlockedExcludingDpkgBroken, not Blocked: a broken dpkg database is the expected
	// precondition for this repair — gating it on "dpkg must already be healthy" would make
	// it permanently unable to run against the exact state it exists to fix. Disk space and
	// clock skew still block normally.
	safety := EvaluateGatedAPTRepairSafety(exec)
	if blocked, reason := safety.BlockedExcludingDpkgBroken(); blocked {
		result.Reason = reason
		return result
	}

	result.ApplyResult = ApplyAPTFixBrokenRepair(exec, preview)
	if result.ApplyResult.Applied {
		result.Status = APTFixBrokenApprovalStatusApplied
		return result
	}

	result.Status = APTFixBrokenApprovalStatusFailed
	if result.ApplyResult.Error != nil {
		result.Reason = result.ApplyResult.Error.Error()
	} else {
		result.Reason = "APT fix-broken repair execution did not report success"
	}

	return result
}

const (
	aptFixBrokenAuditPathEnv     = "CROSS_SUITE_FIXBROKEN_AUDIT_PATH"
	defaultAPTFixBrokenAuditPath = "/var/log/cross-suite/repohealer-fixbroken-audit.jsonl"
)

type APTFixBrokenAuditEvent struct {
	Event           string                     `json:"event"`
	OccurredAt      time.Time                  `json:"occurred_at"`
	Status          APTFixBrokenApprovalStatus `json:"status"`
	RepairAttempted bool                       `json:"repair_attempted"`
	Applied         bool                       `json:"applied"`
	RolledBack      bool                       `json:"rolled_back"`
	SnapshotID      string                     `json:"snapshot_id,omitempty"`
	SnapshotPath    string                     `json:"snapshot_path,omitempty"`
	FailureCategory RepairFailureCategory      `json:"failure_category"`
}

func APTFixBrokenAuditPath() string {
	if path := strings.TrimSpace(os.Getenv(aptFixBrokenAuditPathEnv)); path != "" {
		return path
	}
	return defaultAPTFixBrokenAuditPath
}

func BuildAPTFixBrokenAuditEvent(
	result APTFixBrokenApprovalResult,
	occurredAt time.Time,
) APTFixBrokenAuditEvent {
	repair := result.ApplyResult

	event := APTFixBrokenAuditEvent{
		Event:           "apt_fix_broken_install_repair",
		OccurredAt:      occurredAt.UTC(),
		Status:          result.Status,
		RepairAttempted: repair.Attempted,
		Applied:         repair.Applied,
		RolledBack:      repair.RolledBack,
		SnapshotID:      repair.Snapshot.ID,
		SnapshotPath:    repair.Snapshot.Path,
	}

	switch result.Status {
	case APTFixBrokenApprovalStatusBlocked:
		event.FailureCategory = RepairFailureBlocked
	case APTFixBrokenApprovalStatusDeclined:
		event.FailureCategory = RepairFailureDeclined
	case APTFixBrokenApprovalStatusApplied:
		event.FailureCategory = RepairFailureNone
	case APTFixBrokenApprovalStatusFailed:
		switch {
		case strings.Contains(strings.ToLower(result.Reason), "snapshot"):
			event.FailureCategory = RepairFailureSnapshot
		case strings.Contains(strings.ToLower(result.Reason), "rollback"):
			event.FailureCategory = RepairFailureRollback
		case strings.Contains(strings.ToLower(result.Reason), "dpkg --audit"),
			strings.Contains(strings.ToLower(result.Reason), "apt-get update"):
			event.FailureCategory = RepairFailureVerification
		default:
			event.FailureCategory = RepairFailureExecution
		}
	default:
		event.FailureCategory = RepairFailureUnknown
	}

	return event
}

func AppendAPTFixBrokenAuditEvent(path string, event APTFixBrokenAuditEvent) error {
	return appendDeb822RepairAuditJSONL(path, event)
}
