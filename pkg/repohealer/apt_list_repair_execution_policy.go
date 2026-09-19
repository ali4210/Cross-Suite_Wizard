package repohealer

import (
	"os"
	"strings"
)

const hashicorpAPTListRepairExecutionEnabledEnv = "CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED"

func HashiCorpAPTListRepairExecutionEnabled() bool {
	return strings.EqualFold(
		strings.TrimSpace(
			os.Getenv(hashicorpAPTListRepairExecutionEnabledEnv),
		),
		"true",
	)
}
