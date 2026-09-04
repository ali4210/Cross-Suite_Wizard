package playbook

import (
	"strconv"
	"strings"

	"cross-ssh/pkg/repohealer"
)

func selectRepositoryRepairAction(
	actions []repohealer.RepairAction,
	input string,
) (repohealer.RepairAction, bool) {
	trimmed := strings.TrimSpace(input)

	if trimmed == "" ||
		trimmed == "0" ||
		strings.EqualFold(trimmed, "q") ||
		strings.EqualFold(trimmed, "back") {
		return repohealer.RepairAction{}, false
	}

	index, err := strconv.Atoi(trimmed)
	if err != nil || index < 1 || index > len(actions) {
		return repohealer.RepairAction{}, false
	}

	return actions[index-1], true
}
