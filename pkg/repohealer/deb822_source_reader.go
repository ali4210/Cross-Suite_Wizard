package repohealer

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	deb822SourceReadBegin = "CROSS_SUITE_DEB822_SOURCE_BEGIN"
	deb822SourceReadEnd   = "CROSS_SUITE_DEB822_SOURCE_END"
	deb822SourceReadError = "CROSS_SUITE_DEB822_SOURCE_ERROR"
	maxDeb822SourceBytes  = 64 * 1024
)

func ReadApprovedDeb822Source(
	exec Executor,
	action RepairAction,
) (string, error) {
	if err := validateApprovedDeb822SourcePath(action.SourceFile); err != nil {
		return "", err
	}

	sourceFile := strings.TrimSpace(action.SourceFile)

	script := fmt.Sprintf(`
set -eu

SOURCE_FILE=%s
MAX_BYTES=%d
ERROR_MARKER=%s
BEGIN_MARKER=%s
END_MARKER=%s

fail() {
	reason="$1"
	shift
	printf '%%s|%%s' "$ERROR_MARKER" "$reason"
	for detail in "$@"; do
		printf '|%%s' "$detail"
	done
	printf '\n'
	exit 1
}

if [ ! -e "$SOURCE_FILE" ]; then
	fail missing
fi

if [ -L "$SOURCE_FILE" ]; then
	fail symlink
fi

if [ ! -f "$SOURCE_FILE" ]; then
	fail not_regular_file
fi

metadata="$(stat -c '%%u|%%g|%%a|%%s' -- "$SOURCE_FILE")"
IFS='|' read -r uid gid mode size <<EOF_METADATA
$metadata
EOF_METADATA

if [ "$uid" != "0" ] || [ "$gid" != "0" ]; then
	fail unexpected_owner "uid=$uid" "gid=$gid"
fi

case "$mode" in
	[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
	*) fail invalid_mode "mode=$mode" ;;
esac

mode_value=$((8#$mode))
if [ $((mode_value & 0022)) -ne 0 ]; then
	fail writable_by_group_or_other "mode=$mode"
fi

case "$size" in
	''|*[!0-9]*) fail invalid_size "size=$size" ;;
esac

if [ "$size" -gt "$MAX_BYTES" ]; then
	fail file_too_large "size=$size" "max=$MAX_BYTES"
fi

if [ ! -r "$SOURCE_FILE" ]; then
	fail unreadable
fi

printf '%%s\n' "$BEGIN_MARKER"
base64 -- "$SOURCE_FILE"
printf '\n%%s\n' "$END_MARKER"
`,
		shellQuote(sourceFile),
		maxDeb822SourceBytes,
		shellQuote(deb822SourceReadError),
		shellQuote(deb822SourceReadBegin),
		shellQuote(deb822SourceReadEnd),
	)

	output, err := exec.RunSudoWithLabel(
		script,
		"Reading Approved Deb822 APT Source",
	)

	document, parseErr := parseApprovedDeb822SourceReadOutput(output)
	if parseErr != nil {
		return "", parseErr
	}

	if err != nil {
		return "", fmt.Errorf("Deb822 source read failed: %w", err)
	}

	return document, nil
}

func parseApprovedDeb822SourceReadOutput(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", fmt.Errorf("Deb822 source read failed: empty reader output")
	}

	lines := strings.Split(trimmed, "\n")
	if strings.HasPrefix(lines[0], deb822SourceReadError+"|") {
		return "", fmt.Errorf(
			"Deb822 source read blocked: %s",
			strings.TrimPrefix(lines[0], deb822SourceReadError+"|"),
		)
	}

	if len(lines) != 3 ||
		strings.TrimSpace(lines[0]) != deb822SourceReadBegin ||
		strings.TrimSpace(lines[2]) != deb822SourceReadEnd {
		return "", fmt.Errorf(
			"Deb822 source read failed: invalid reader output envelope",
		)
	}

	encoded := strings.TrimSpace(lines[1])
	if encoded == "" {
		return "", fmt.Errorf(
			"Deb822 source read failed: source content was empty",
		)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf(
			"Deb822 source read failed: invalid base64 content: %w",
			err,
		)
	}

	if len(decoded) == 0 {
		return "", fmt.Errorf(
			"Deb822 source read failed: source content was empty",
		)
	}

	if len(decoded) > maxDeb822SourceBytes {
		return "", fmt.Errorf(
			"Deb822 source read failed: decoded content exceeds %d bytes",
			maxDeb822SourceBytes,
		)
	}

	return string(decoded), nil
}

func deb822ReaderOutput(document string) string {
	return strings.Join([]string{
		deb822SourceReadBegin,
		base64.StdEncoding.EncodeToString([]byte(document)),
		deb822SourceReadEnd,
	}, "\n")
}

func deb822ReaderError(reason string) string {
	return deb822SourceReadError + "|" + reason
}
