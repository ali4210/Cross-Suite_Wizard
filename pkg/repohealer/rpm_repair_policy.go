package repohealer

import (
	"os"
	"strings"
)

// RPMRepairExecutionEnabledEnv is the operator-policy environment variable that must be
// set to exactly "true" before any known-vendor dnf/yum/zypper repair is allowed to apply
// — mirroring HashiCorpAPTListRepairExecutionEnabledEnv/CustomKeyRepairExecutionEnabledEnv.
// This is checked inside applyKnownRPMRepairActionWithVerification itself (not only by a
// caller), so the gate holds regardless of which UI path reaches it. A sudo-safe example
// for an operator enabling this for one SSH command, without ever putting it in a shell
// history file or a long-lived environment:
//
//	ssh host 'sudo env CROSS_SUITE_RPM_REPAIR_ENABLED=true cross-ssh-agent-command'
const RPMRepairExecutionEnabledEnv = "CROSS_SUITE_RPM_REPAIR_ENABLED"

// RPMRepairExecutionEnabled reports whether the operator-policy gate above is set.
func RPMRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(RPMRepairExecutionEnabledEnv)),
		"true",
	)
}
