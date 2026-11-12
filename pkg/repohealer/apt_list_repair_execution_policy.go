package repohealer

import (
	"os"
	"strings"
)

// HashiCorpAPTListRepairExecutionEnabledEnv is the operator-policy environment variable that
// must be set to exactly "true" before the HashiCorp APT-list repair is allowed to apply.
// Exported so callers (e.g. the playbook UI) can show the exact variable name without
// duplicating the string literal.
const HashiCorpAPTListRepairExecutionEnabledEnv = "CROSS_SUITE_APTLIST_REPAIR_ENABLED"

// HashiCorpAPTListRepairExecutionEnabled mirrors Deb822RepairExecutionEnabled's operator-policy
// gate: even a fully approved, typed-"yes" HashiCorp APT-list repair will not apply unless the
// operator has explicitly opted in for this host.
func HashiCorpAPTListRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(HashiCorpAPTListRepairExecutionEnabledEnv)),
		"true",
	)
}
