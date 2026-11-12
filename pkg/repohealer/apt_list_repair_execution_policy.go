package repohealer

import (
	"os"
	"strings"
)

const hashicorpAPTListRepairExecutionEnabledEnv = "CROSS_SUITE_APTLIST_REPAIR_ENABLED"

// HashiCorpAPTListRepairExecutionEnabled mirrors Deb822RepairExecutionEnabled's operator-policy
// gate: even a fully approved, typed-"yes" HashiCorp APT-list repair will not apply unless the
// operator has explicitly opted in for this host.
func HashiCorpAPTListRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(hashicorpAPTListRepairExecutionEnabledEnv)),
		"true",
	)
}
