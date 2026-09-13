package repohealer

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	deb822DoctorProbeBegin = "CROSS_SUITE_DEB822_DOCTOR_BEGIN"
	deb822DoctorProbeEnd   = "CROSS_SUITE_DEB822_DOCTOR_END"
	deb822DoctorProbeError = "CROSS_SUITE_DEB822_DOCTOR_ERROR"

	deb822DoctorProbeLabel = "Probing Deb822 APT Repair Readiness"
)

type Deb822DoctorFileState string

const (
	Deb822DoctorFileStatePresent     Deb822DoctorFileState = "present"
	Deb822DoctorFileStateMissing     Deb822DoctorFileState = "missing"
	Deb822DoctorFileStateSymlink     Deb822DoctorFileState = "symlink"
	Deb822DoctorFileStateNotRegular  Deb822DoctorFileState = "not_regular"
	Deb822DoctorFileStateUnsafeOwner Deb822DoctorFileState = "unsafe_owner"
	Deb822DoctorFileStateUnsafeMode  Deb822DoctorFileState = "unsafe_mode"
	Deb822DoctorFileStateUnreadable  Deb822DoctorFileState = "unreadable"
	Deb822DoctorFileStateInvalid     Deb822DoctorFileState = "invalid"
	Deb822DoctorFileStateUnknown     Deb822DoctorFileState = "unknown"
)

type Deb822DoctorRemoteFile struct {
	State Deb822DoctorFileState
	Mode  string
	Size  int64
}

type Deb822DoctorRemoteProbe struct {
	APTAvailable       bool
	Source             Deb822DoctorRemoteFile
	Keyring            Deb822DoctorRemoteFile
	PackageLocksActive bool
}

func ProbeSelectedDeb822RepairMetadata(
	exec Executor,
	action RepairAction,
) (Deb822DoctorRemoteProbe, error) {
	if err := validateDeb822DoctorProbeAction(action); err != nil {
		return Deb822DoctorRemoteProbe{}, err
	}

	script := fmt.Sprintf(`
set -eu

SOURCE_FILE=%s
KEYRING_PATH=%s
BEGIN_MARKER=%s
END_MARKER=%s
ERROR_MARKER=%s

emit_file_state() {
	name="$1"
	target="$2"

	if [ ! -e "$target" ]; then
		printf 'file|%%s|missing|||\\n' "$name"
		return
	fi

	if [ -L "$target" ]; then
		printf 'file|%%s|symlink|||\\n' "$name"
		return
	fi

	if [ ! -f "$target" ]; then
		printf 'file|%%s|not_regular|||\\n' "$name"
		return
	fi

	metadata="$(stat -c '%%u|%%g|%%a|%%s' -- "$target")"
	IFS='|' read -r uid gid mode size <<EOF_METADATA
$metadata
EOF_METADATA

	case "$mode" in
		[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
		*) printf 'file|%%s|invalid|||\\n' "$name"; return ;;
	esac

	case "$size" in
		''|*[!0-9]*) printf 'file|%%s|invalid|||\\n' "$name"; return ;;
	esac

	mode_value=$((8#$mode))
	if [ "$uid" != "0" ] || [ "$gid" != "0" ]; then
		printf 'file|%%s|unsafe_owner|%%s|%%s\\n' "$name" "$mode" "$size"
		return
	fi

	if [ $((mode_value & 0022)) -ne 0 ]; then
		printf 'file|%%s|unsafe_mode|%%s|%%s\\n' "$name" "$mode" "$size"
		return
	fi

	if [ ! -r "$target" ]; then
		printf 'file|%%s|unreadable|%%s|%%s\\n' "$name" "$mode" "$size"
		return
	fi

	printf 'file|%%s|present|%%s|%%s\\n' "$name" "$mode" "$size"
}

printf '%%s\\n' "$BEGIN_MARKER"

if command -v apt-get >/dev/null 2>&1; then
	printf '%%s\\n' 'apt_get|present'
else
	printf '%%s\\n' 'apt_get|missing'
fi

emit_file_state source "$SOURCE_FILE"
emit_file_state keyring "$KEYRING_PATH"

if command -v fuser >/dev/null 2>&1 && \
	fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
	/var/lib/apt/lists/lock /var/cache/apt/archives/lock \
	>/dev/null 2>&1; then
	printf '%%s\\n' 'locks|active'
else
	printf '%%s\\n' 'locks|clear'
fi

printf '%%s\\n' "$END_MARKER"
`,
		shellQuote(action.SourceFile),
		shellQuote(action.KeyringPath),
		shellQuote(deb822DoctorProbeBegin),
		shellQuote(deb822DoctorProbeEnd),
		shellQuote(deb822DoctorProbeError),
	)

	output, err := exec.RunSudoWithLabel(script, deb822DoctorProbeLabel)

	probe, parseErr := parseDeb822DoctorProbeOutput(output)
	if parseErr != nil {
		return Deb822DoctorRemoteProbe{}, parseErr
	}
	if err != nil {
		return Deb822DoctorRemoteProbe{}, fmt.Errorf(
			"Deb822 Doctor remote probe failed: %w",
			err,
		)
	}

	return probe, nil
}

func validateDeb822DoctorProbeAction(action RepairAction) error {
	if action.SourceFormat != SourceFormatDeb822 {
		return fmt.Errorf(
			"Deb822 Doctor remote probe blocked: action source format %q is not Deb822",
			action.SourceFormat,
		)
	}

	if strings.TrimSpace(action.ID) == "" ||
		strings.TrimSpace(action.ProfileID) == "" ||
		strings.TrimSpace(action.RepositoryURL) == "" ||
		strings.TrimSpace(action.SourceFile) == "" ||
		strings.TrimSpace(action.KeyringPath) == "" {
		return fmt.Errorf(
			"Deb822 Doctor remote probe blocked: action binding is incomplete",
		)
	}

	if err := validateApprovedDeb822SourcePath(action.SourceFile); err != nil {
		return err
	}

	profile, ok := FindVendorProfileByID(ManagerAPT, action.ProfileID)
	if !ok {
		return fmt.Errorf(
			"Deb822 Doctor remote probe blocked: profile %q is not supported",
			action.ProfileID,
		)
	}

	if action.KeyringPath != profile.KeyringPath {
		return fmt.Errorf(
			"Deb822 Doctor remote probe blocked: action keyring path does not match verified profile",
		)
	}

	if !profileAllowsExactRepositoryURL(profile, action.RepositoryURL) {
		return fmt.Errorf(
			"Deb822 Doctor remote probe blocked: action repository URL does not match verified profile",
		)
	}

	return nil
}

func parseDeb822DoctorProbeOutput(
	output string,
) (Deb822DoctorRemoteProbe, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return Deb822DoctorRemoteProbe{}, fmt.Errorf(
			"Deb822 Doctor remote probe failed: empty probe output",
		)
	}

	lines := strings.Split(trimmed, "\n")
	if len(lines) < 6 ||
		strings.TrimSpace(lines[0]) != deb822DoctorProbeBegin ||
		strings.TrimSpace(lines[len(lines)-1]) != deb822DoctorProbeEnd {
		return Deb822DoctorRemoteProbe{}, fmt.Errorf(
			"Deb822 Doctor remote probe failed: invalid probe output envelope",
		)
	}

	var probe Deb822DoctorRemoteProbe
	seen := map[string]bool{}

	for _, rawLine := range lines[1 : len(lines)-1] {
		line := strings.TrimSpace(rawLine)
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			return Deb822DoctorRemoteProbe{}, fmt.Errorf(
				"Deb822 Doctor remote probe failed: invalid probe record",
			)
		}

		switch parts[0] {
		case "apt_get":
			if len(parts) != 2 || seen["apt_get"] {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: invalid apt_get record",
				)
			}
			if parts[1] == "present" {
				probe.APTAvailable = true
			} else if parts[1] != "missing" {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: invalid apt_get state",
				)
			}
			seen["apt_get"] = true

		case "locks":
			if len(parts) != 2 || seen["locks"] {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: invalid locks record",
				)
			}
			if parts[1] == "active" {
				probe.PackageLocksActive = true
			} else if parts[1] != "clear" {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: invalid lock state",
				)
			}
			seen["locks"] = true

		case "file":
			if len(parts) != 5 {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: invalid file record",
				)
			}

			name := parts[1]
			if name != "source" && name != "keyring" {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: unknown file record",
				)
			}
			if seen["file:"+name] {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: duplicate file record",
				)
			}

			state, err := parseDeb822DoctorFileState(parts[2])
			if err != nil {
				return Deb822DoctorRemoteProbe{}, err
			}

			file := Deb822DoctorRemoteFile{
				State: state,
				Mode:  strings.TrimSpace(parts[3]),
			}
			if parts[4] != "" {
				size, err := strconv.ParseInt(parts[4], 10, 64)
				if err != nil || size < 0 {
					return Deb822DoctorRemoteProbe{}, fmt.Errorf(
						"Deb822 Doctor remote probe failed: invalid file size",
					)
				}
				file.Size = size
			}

			if state == Deb822DoctorFileStatePresent ||
				state == Deb822DoctorFileStateUnsafeOwner ||
				state == Deb822DoctorFileStateUnsafeMode ||
				state == Deb822DoctorFileStateUnreadable {
				if file.Mode == "" || parts[4] == "" {
					return Deb822DoctorRemoteProbe{}, fmt.Errorf(
						"Deb822 Doctor remote probe failed: missing file metadata",
					)
				}
			} else if file.Mode != "" || parts[4] != "" {
				return Deb822DoctorRemoteProbe{}, fmt.Errorf(
					"Deb822 Doctor remote probe failed: unexpected file metadata",
				)
			}

			if name == "source" {
				probe.Source = file
			} else {
				probe.Keyring = file
			}
			seen["file:"+name] = true

		default:
			return Deb822DoctorRemoteProbe{}, fmt.Errorf(
				"Deb822 Doctor remote probe failed: unknown probe record",
			)
		}
	}

	for _, required := range []string{
		"apt_get",
		"file:source",
		"file:keyring",
		"locks",
	} {
		if !seen[required] {
			return Deb822DoctorRemoteProbe{}, fmt.Errorf(
				"Deb822 Doctor remote probe failed: missing required probe record %q",
				required,
			)
		}
	}

	return probe, nil
}

func parseDeb822DoctorFileState(
	value string,
) (Deb822DoctorFileState, error) {
	state := Deb822DoctorFileState(strings.TrimSpace(value))

	switch state {
	case Deb822DoctorFileStatePresent,
		Deb822DoctorFileStateMissing,
		Deb822DoctorFileStateSymlink,
		Deb822DoctorFileStateNotRegular,
		Deb822DoctorFileStateUnsafeOwner,
		Deb822DoctorFileStateUnsafeMode,
		Deb822DoctorFileStateUnreadable,
		Deb822DoctorFileStateInvalid:
		return state, nil
	default:
		return Deb822DoctorFileStateUnknown, fmt.Errorf(
			"Deb822 Doctor remote probe failed: invalid file state",
		)
	}
}
