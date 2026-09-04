package repohealer

import (
	"strings"
	"time"
)

func CollectSystemdJournal(exec Executor) []CommandEvidence {
	commands := []string{
		"journalctl -u apt-daily.service -u apt-daily-upgrade.service -u unattended-upgrades.service --since '-24 hours' --no-pager -o short-iso 2>&1 || true",
		"journalctl -p warning..alert --since '-24 hours' --no-pager -o short-iso 2>&1 || true",
	}

	evidence := make([]CommandEvidence, 0, len(commands))

	for _, command := range commands {
		started := time.Now()
		output, err := exec.Run(command)

		exitCode := 0
		if err != nil {
			exitCode = 1
		}

		evidence = append(evidence, CommandEvidence{
			Command:  command,
			Output:   strings.TrimSpace(output),
			ExitCode: exitCode,
			Duration: time.Since(started),
		})
	}

	return evidence
}
