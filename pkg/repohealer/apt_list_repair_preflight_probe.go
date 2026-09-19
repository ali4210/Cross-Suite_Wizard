package repohealer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const hashicorpAPTListRepairPreflightProbeVersion = "1"

var (
	hashicorpAPTListRepairPreflightProbeModePattern   = regexp.MustCompile(`^[0-7]{3}$`)
	hashicorpAPTListRepairPreflightProbeSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func parseHashiCorpAPTListRepairPreflightProbeOutput(
	output string,
) (HashiCorpAPTListRepairPreflightProbe, error) {
	if output == "" {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output is empty",
		)
	}
	if strings.Contains(output, "\r") {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output contains an invalid record line ending",
		)
	}
	if strings.HasSuffix(output, "\n") {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output contains a blank record",
		)
	}

	lines := strings.Split(output, "\n")
	var probe HashiCorpAPTListRepairPreflightProbe

	seenVersion := false
	seenSource := false
	seenKeyring := false
	seenLock := false
	seenTools := map[string]bool{}

	requiredTools := map[string]func(bool){
		"apt-get": func(available bool) {
			probe.APTAvailable = available
		},
		"gpg": func(available bool) {
			probe.GPGAvailable = available
		},
		"install": func(available bool) {
			probe.InstallAvailable = available
		},
		"mv": func(available bool) {
			probe.MVAvailable = available
		},
		"sha256sum": func(available bool) {
			probe.SHA256Available = available
		},
	}

	for _, line := range lines {
		if line == "" {
			return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
				"HashiCorp APT-list repair preflight probe output contains a blank record",
			)
		}

		parts := strings.Split(line, "|")
		switch parts[0] {
		case "VERSION":
			if seenVersion {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output contains a duplicate version record",
				)
			}
			if len(parts) != 2 ||
				parts[1] != hashicorpAPTListRepairPreflightProbeVersion {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an unsupported version",
				)
			}
			seenVersion = true

		case "FILE":
			if len(parts) < 3 {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid file record",
				)
			}

			file, err := parseHashiCorpAPTListRepairPreflightProbeFile(
				parts[2:],
			)
			if err != nil {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid %s file record: %w",
					parts[1],
					err,
				)
			}

			switch parts[1] {
			case "source":
				if seenSource {
					return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
						"HashiCorp APT-list repair preflight probe output contains a duplicate source record",
					)
				}
				if file.State == HashiCorpAPTListRepairPreflightFileMissing {
					return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
						"HashiCorp APT-list repair preflight probe output has a missing source file",
					)
				}
				probe.Source = file
				seenSource = true

			case "keyring":
				if seenKeyring {
					return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
						"HashiCorp APT-list repair preflight probe output contains a duplicate keyring record",
					)
				}
				probe.Keyring = file
				seenKeyring = true

			default:
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an unknown file record %q",
					parts[1],
				)
			}

		case "TOOL":
			if len(parts) != 3 {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid tool record",
				)
			}

			setAvailable, ok := requiredTools[parts[1]]
			if !ok {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an unknown tool %q",
					parts[1],
				)
			}
			if seenTools[parts[1]] {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output contains a duplicate tool record %q",
					parts[1],
				)
			}

			switch parts[2] {
			case "0":
				setAvailable(false)
			case "1":
				setAvailable(true)
			default:
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid availability value for tool %q",
					parts[1],
				)
			}
			seenTools[parts[1]] = true

		case "LOCK":
			if seenLock {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output contains a duplicate lock record",
				)
			}
			if len(parts) != 3 || parts[1] != "apt_dpkg" {
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid lock record",
				)
			}

			switch parts[2] {
			case "0":
				probe.APTLockActive = false
			case "1":
				probe.APTLockActive = true
			default:
				return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
					"HashiCorp APT-list repair preflight probe output has an invalid lock value",
				)
			}
			seenLock = true

		default:
			return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
				"HashiCorp APT-list repair preflight probe output contains an unknown record %q",
				parts[0],
			)
		}
	}

	if !seenVersion {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output is missing a version record",
		)
	}
	if !seenSource {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output is missing a source record",
		)
	}
	if !seenKeyring {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output is missing a keyring record",
		)
	}
	for _, tool := range []string{
		"apt-get",
		"gpg",
		"install",
		"mv",
		"sha256sum",
	} {
		if !seenTools[tool] {
			return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
				"HashiCorp APT-list repair preflight probe output is missing tool record %q",
				tool,
			)
		}
	}
	if !seenLock {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe output is missing a lock record",
		)
	}

	return probe, nil
}

func parseHashiCorpAPTListRepairPreflightProbeFile(
	parts []string,
) (HashiCorpAPTListRepairPreflightFile, error) {
	if len(parts) < 1 {
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file state is missing",
		)
	}

	state := HashiCorpAPTListRepairPreflightFileState(parts[0])
	switch state {
	case HashiCorpAPTListRepairPreflightFileMissing,
		HashiCorpAPTListRepairPreflightFileSymlink,
		HashiCorpAPTListRepairPreflightFileNotRegular,
		HashiCorpAPTListRepairPreflightFileUnreadable:
		if len(parts) != 1 {
			return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
				"file state %q must not include metadata",
				state,
			)
		}
		return HashiCorpAPTListRepairPreflightFile{
			State: state,
		}, nil

	case HashiCorpAPTListRepairPreflightFilePresent,
		HashiCorpAPTListRepairPreflightFileUnsafeOwner,
		HashiCorpAPTListRepairPreflightFileUnsafeMode:
		if len(parts) != 5 {
			return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
				"file state %q requires exactly four metadata fields",
				state,
			)
		}

	default:
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file state %q is invalid",
			state,
		)
	}

	uid, err := strconv.Atoi(parts[1])
	if err != nil || uid < 0 {
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file UID %q is invalid",
			parts[1],
		)
	}

	if !hashicorpAPTListRepairPreflightProbeModePattern.MatchString(parts[2]) {
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file mode %q is invalid",
			parts[2],
		)
	}

	size, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || size < 0 {
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file size %q is invalid",
			parts[3],
		)
	}

	if !hashicorpAPTListRepairPreflightProbeSHA256Pattern.MatchString(parts[4]) {
		return HashiCorpAPTListRepairPreflightFile{}, fmt.Errorf(
			"file SHA-256 %q is invalid",
			parts[4],
		)
	}

	return HashiCorpAPTListRepairPreflightFile{
		State:  state,
		UID:    uid,
		Mode:   parts[2],
		Size:   size,
		SHA256: parts[4],
	}, nil
}

const hashicorpAPTListRepairPreflightProbeLabel = "repohealer-hashicorp-apt-list-repair-preflight"

func ProbeHashiCorpAPTListRepairPreflight(
	exec Executor,
	request HashiCorpAPTListRepairExecutionRequest,
) (HashiCorpAPTListRepairPreflightProbe, error) {
	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe blocked: request is invalid: %w",
			err,
		)
	}

	script, err := buildHashiCorpAPTListRepairPreflightProbeScript(request)
	if err != nil {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe blocked: %w",
			err,
		)
	}

	output, err := exec.RunSudoWithLabel(
		script,
		hashicorpAPTListRepairPreflightProbeLabel,
	)
	if err != nil {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe failed: %w",
			err,
		)
	}

	probe, err := parseHashiCorpAPTListRepairPreflightProbeOutput(output)
	if err != nil {
		return HashiCorpAPTListRepairPreflightProbe{}, fmt.Errorf(
			"HashiCorp APT-list repair preflight probe returned unsafe output: %w",
			err,
		)
	}

	return probe, nil
}

func buildHashiCorpAPTListRepairPreflightProbeScript(
	request HashiCorpAPTListRepairExecutionRequest,
) (string, error) {
	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		return "", fmt.Errorf("request is invalid: %w", err)
	}

	sourcePath := shellSingleQuote(request.SourceFile)
	keyringPath := shellSingleQuote(request.KeyringPath)

	return fmt.Sprintf(`set -eu

emit() {
	printf '%%s' "$1"
}

emit_line() {
	if [ "$emitted" -eq 1 ]; then
		printf '\n'
	fi
	emit "$1"
	emitted=1
}

probe_file() {
	name="$1"
	path="$2"

	if [ -L "$path" ]; then
		emit_line "FILE|$name|symlink"
		return
	fi

	if [ ! -e "$path" ]; then
		emit_line "FILE|$name|missing"
		return
	fi

	if [ ! -f "$path" ]; then
		emit_line "FILE|$name|not_regular"
		return
	fi

	if [ "$stat_available" != "1" ]; then
		emit_line "FILE|$name|unreadable"
		return
	fi

	if ! metadata=$(stat -c '%%u|%%a|%%s' -- "$path" 2>/dev/null); then
		emit_line "FILE|$name|unreadable"
		return
	fi

	uid=${metadata%%|*}
	rest=${metadata#*|}
	mode=${rest%%|*}
	size=${rest#*|}

	if [ "$sha256sum_available" != "1" ]; then
		emit_line "FILE|$name|unreadable"
		return
	fi

	if ! hash=$(sha256sum -- "$path" 2>/dev/null); then
		emit_line "FILE|$name|unreadable"
		return
	fi
	hash=${hash%% *}

	if [ "$uid" != "0" ]; then
		emit_line "FILE|$name|unsafe_owner|$uid|$mode|$size|$hash"
		return
	fi

	if [ "$mode" != "644" ]; then
		emit_line "FILE|$name|unsafe_mode|$uid|$mode|$size|$hash"
		return
	fi

	emit_line "FILE|$name|present|$uid|$mode|$size|$hash"
}

probe_tool() {
	name="$1"
	if command -v "$name" >/dev/null 2>&1; then
		if [ "$name" = "sha256sum" ]; then
			sha256sum_available=1
		fi
		emit_line "TOOL|$name|1"
	else
		if [ "$name" = "sha256sum" ]; then
			sha256sum_available=0
		fi
		emit_line "TOOL|$name|0"
	fi
}

probe_lock() {
	if ! command -v fuser >/dev/null 2>&1; then
		emit_line "LOCK|apt_dpkg|1"
		return
	fi

	set +e
	owners="$(fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
		/var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null)"
	status=$?
	set -e

	if [ "$status" -eq 0 ] && [ -n "$owners" ]; then
		emit_line "LOCK|apt_dpkg|1"
		return
	fi

	if [ "$status" -eq 1 ] && [ -z "$owners" ]; then
		emit_line "LOCK|apt_dpkg|0"
		return
	fi

	emit_line "LOCK|apt_dpkg|1"
}

emitted=0
stat_available=0
sha256sum_available=0
if command -v stat >/dev/null 2>&1; then
	stat_available=1
fi
emit_line "VERSION|1"
probe_tool "apt-get"
probe_tool "gpg"
probe_tool "install"
probe_tool "mv"
probe_tool "sha256sum"
probe_file "source" %s
probe_file "keyring" %s
probe_lock`, sourcePath, keyringPath), nil
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
