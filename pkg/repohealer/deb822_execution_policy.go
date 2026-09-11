package repohealer

import (
	"os"
	"strings"
)

const deb822RepairExecutionEnabledEnv = "CROSS_SUITE_DEB822_REPAIR_ENABLED"

func Deb822RepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv(deb822RepairExecutionEnabledEnv)),
		"true",
	)
}
