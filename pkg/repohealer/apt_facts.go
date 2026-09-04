package repohealer

import (
	"strings"
	"time"
)

func CollectAPTFacts(exec Executor, fallback TargetFacts) (TargetFacts, CommandEvidence) {
	facts := fallback

	command := `
set +e

if [ -f /etc/os-release ]; then
	. /etc/os-release
	printf 'os_id=%s\n' "${ID:-}"
	printf 'os_id_like=%s\n' "${ID_LIKE:-}"
	printf 'os_version_id=%s\n' "${VERSION_ID:-}"
	printf 'os_codename=%s\n' "${VERSION_CODENAME:-}"
fi

if command -v dpkg >/dev/null 2>&1; then
	printf 'apt_architecture=%s\n' "$(dpkg --print-architecture 2>/dev/null)"
fi
`

	started := time.Now()
	output, err := exec.RunSudo(command)

	exitCode := 0
	if err != nil {
		exitCode = 1
	}

	evidence := CommandEvidence{
		Command:  "collect precise APT operating-system and architecture facts",
		Output:   strings.TrimSpace(output),
		ExitCode: exitCode,
		Duration: time.Since(started),
	}

	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}

		switch key {
		case "os_id":
			if value != "" {
				facts.Distribution = strings.ToLower(value)
			}
		case "os_version_id":
			if value != "" {
				facts.Version = value
			}
		case "os_codename":
			if value != "" {
				facts.Codename = strings.ToLower(value)
			}
		case "apt_architecture":
			if value != "" {
				facts.Architecture = strings.ToLower(value)
			}
		}
	}

	return facts, evidence
}
