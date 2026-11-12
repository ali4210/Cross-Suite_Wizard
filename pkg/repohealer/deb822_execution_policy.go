package repohealer

import (
	"os"
	"strings"
)

// Deb822RepairExecutionEnabledEnv is the operator-policy environment variable that must be set
// to exactly "true" before a Deb822 repair is allowed to apply. Exported so callers (e.g. the
// playbook UI) can show the exact variable name without duplicating the string literal.
const Deb822RepairExecutionEnabledEnv = "CROSS_SUITE_DEB822_REPAIR_ENABLED"

func Deb822RepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(Deb822RepairExecutionEnabledEnv)),
		"true",
	)
}
