package repohealer

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	aptListDoctorProbeBegin = "CROSS_SUITE_APT_LIST_DOCTOR_BEGIN"
	aptListDoctorProbeEnd   = "CROSS_SUITE_APT_LIST_DOCTOR_END"

	aptListDoctorProbeLabel = "Probing APT List Keyring Metadata"
)

type APTListDoctorFileState string

const (
	APTListDoctorFileStatePresent     APTListDoctorFileState = "present"
	APTListDoctorFileStateMissing     APTListDoctorFileState = "missing"
	APTListDoctorFileStateSymlink     APTListDoctorFileState = "symlink"
	APTListDoctorFileStateNotRegular  APTListDoctorFileState = "not_regular"
	APTListDoctorFileStateUnsafeOwner APTListDoctorFileState = "unsafe_owner"
	APTListDoctorFileStateUnsafeMode  APTListDoctorFileState = "unsafe_mode"
	APTListDoctorFileStateUnreadable  APTListDoctorFileState = "unreadable"
	APTListDoctorFileStateInvalid     APTListDoctorFileState = "invalid"
	APTListDoctorFileStateUnknown     APTListDoctorFileState = "unknown"
)

type APTListDoctorRemoteFile struct {
	State APTListDoctorFileState
	Mode  string
	Size  int64
}

type APTListDoctorRemoteProbe struct {
	APTAvailable        bool
	GPGAvailable        bool
	Source              APTListDoctorRemoteFile
	Keyring             APTListDoctorRemoteFile
	KeyringFingerprints []string
}

func ProbeSelectedAPTListRepairMetadata(
	exec Executor,
	action RepairAction,
) (APTListDoctorRemoteProbe, error) {
	if err := validateAPTListDoctorProbeAction(action); err != nil {
		return APTListDoctorRemoteProbe{}, err
	}

	script := fmt.Sprintf(`
set -eu

SOURCE_FILE=%s
KEYRING_PATH=%s
BEGIN_MARKER=%s
END_MARKER=%s

emit_file_state() {
	name="$1"
	target="$2"

	if [ ! -e "$target" ]; then
		printf 'file|%%s|missing|||\n' "$name"
		return
	fi

	if [ -L "$target" ]; then
		printf 'file|%%s|symlink|||\n' "$name"
		return
	fi

	if [ ! -f "$target" ]; then
		printf 'file|%%s|not_regular|||\n' "$name"
		return
	fi

	metadata="$(stat -c '%%u|%%g|%%a|%%s' -- "$target")"
	IFS='|' read -r uid gid mode size <<EOF_METADATA
$metadata
EOF_METADATA

	case "$mode" in
		[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
		*) printf 'file|%%s|invalid|||\n' "$name"; return ;;
	esac

	case "$size" in
		''|*[!0-9]*) printf 'file|%%s|invalid|||\n' "$name"; return ;;
	esac

	mode_value=$((8#$mode))
	if [ "$uid" != "0" ] || [ "$gid" != "0" ]; then
		printf 'file|%%s|unsafe_owner|%%s|%%s\n' "$name" "$mode" "$size"
		return
	fi

	if [ $((mode_value & 0022)) -ne 0 ]; then
		printf 'file|%%s|unsafe_mode|%%s|%%s\n' "$name" "$mode" "$size"
		return
	fi

	if [ ! -r "$target" ]; then
		printf 'file|%%s|unreadable|%%s|%%s\n' "$name" "$mode" "$size"
		return
	fi

	printf 'file|%%s|present|%%s|%%s\n' "$name" "$mode" "$size"
}

printf '%%s\n' "$BEGIN_MARKER"

if command -v apt-get >/dev/null 2>&1; then
	printf '%%s\n' 'apt_get|present'
else
	printf '%%s\n' 'apt_get|missing'
fi

if command -v gpg >/dev/null 2>&1; then
	printf '%%s\n' 'gpg|present'
else
	printf '%%s\n' 'gpg|missing'
fi

emit_file_state source "$SOURCE_FILE"
emit_file_state keyring "$KEYRING_PATH"

if command -v gpg >/dev/null 2>&1 &&
	[ -f "$KEYRING_PATH" ] &&
	[ ! -L "$KEYRING_PATH" ] &&
	[ -r "$KEYRING_PATH" ]; then
	gpg --batch --no-options --no-default-keyring \
		--keyring "$KEYRING_PATH" \
		--with-colons --list-keys 2>/dev/null |
	awk -F: '$1 == "fpr" { print "fpr|" $10 }'
fi

printf '%%s\n' "$END_MARKER"
`,
		shellQuote(action.SourceFile),
		shellQuote(action.KeyringPath),
		shellQuote(aptListDoctorProbeBegin),
		shellQuote(aptListDoctorProbeEnd),
	)

	output, err := exec.RunSudoWithLabel(script, aptListDoctorProbeLabel)

	probe, parseErr := parseAPTListDoctorProbeOutput(output)
	if parseErr != nil {
		return APTListDoctorRemoteProbe{}, parseErr
	}
	if err != nil {
		return APTListDoctorRemoteProbe{}, fmt.Errorf(
			"APT list Doctor remote probe failed: %w",
			err,
		)
	}

	return probe, nil
}

func validateAPTListDoctorProbeAction(action RepairAction) error {
	if action.Eligible || action.RequiresConsent ||
		action.SourceFormat != SourceFormatAPTList {
		return fmt.Errorf(
			"APT list Doctor remote probe blocked: action is not an original blocked APT list action",
		)
	}

	if strings.TrimSpace(action.ID) == "" ||
		strings.TrimSpace(action.ProfileID) == "" ||
		strings.TrimSpace(action.RepositoryURL) == "" ||
		strings.TrimSpace(action.SourceFile) == "" ||
		strings.TrimSpace(action.KeyringPath) == "" {
		return fmt.Errorf(
			"APT list Doctor remote probe blocked: action binding is incomplete",
		)
	}

	if !strings.HasPrefix(action.SourceFile, "/etc/apt/sources.list.d/") ||
		!strings.HasSuffix(action.SourceFile, ".list") ||
		strings.Contains(action.SourceFile, "..") {
		return fmt.Errorf(
			"APT list Doctor remote probe blocked: action source file is outside approved APT list paths",
		)
	}

	if action.ProfileID != HashiCorpAPTListProfileID ||
		action.RepositoryURL != HashiCorpAPTListRepositoryURL ||
		action.KeyringPath != HashiCorpAPTListKeyringPath {
		return fmt.Errorf(
			"APT list Doctor remote probe blocked: action does not match verified HashiCorp profile",
		)
	}

	profile, ok := FindVendorProfileByID(ManagerAPT, action.ProfileID)
	if !ok ||
		!profileAllowsExactRepositoryURL(profile, action.RepositoryURL) ||
		profile.KeyringPath != action.KeyringPath {
		return fmt.Errorf(
			"APT list Doctor remote probe blocked: action does not match verified vendor profile",
		)
	}

	return nil
}

func parseAPTListDoctorProbeOutput(
	output string,
) (APTListDoctorRemoteProbe, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return APTListDoctorRemoteProbe{}, fmt.Errorf(
			"APT list Doctor remote probe failed: empty probe output",
		)
	}

	lines := strings.Split(trimmed, "\n")
	if len(lines) < 6 ||
		strings.TrimSpace(lines[0]) != aptListDoctorProbeBegin ||
		strings.TrimSpace(lines[len(lines)-1]) != aptListDoctorProbeEnd {
		return APTListDoctorRemoteProbe{}, fmt.Errorf(
			"APT list Doctor remote probe failed: invalid probe output envelope",
		)
	}

	var probe APTListDoctorRemoteProbe
	seen := map[string]bool{}

	for _, rawLine := range lines[1 : len(lines)-1] {
		line := strings.TrimSpace(rawLine)
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			return APTListDoctorRemoteProbe{}, fmt.Errorf(
				"APT list Doctor remote probe failed: invalid probe record",
			)
		}

		switch parts[0] {
		case "apt_get", "gpg":
			if len(parts) != 2 || seen[parts[0]] {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: invalid %s record",
					parts[0],
				)
			}

			present := parts[1] == "present"
			if !present && parts[1] != "missing" {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: invalid %s state",
					parts[0],
				)
			}

			if parts[0] == "apt_get" {
				probe.APTAvailable = present
			} else {
				probe.GPGAvailable = present
			}
			seen[parts[0]] = true

		case "file":
			if len(parts) != 5 {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: invalid file record",
				)
			}

			name := parts[1]
			if name != "source" && name != "keyring" {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: unknown file record",
				)
			}
			if seen["file:"+name] {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: duplicate file record",
				)
			}

			file, err := parseAPTListDoctorRemoteFile(parts[2:])
			if err != nil {
				return APTListDoctorRemoteProbe{}, err
			}

			if name == "source" {
				probe.Source = file
			} else {
				probe.Keyring = file
			}
			seen["file:"+name] = true

		case "fpr":
			if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: invalid fingerprint record",
				)
			}

			fingerprint := strings.ToUpper(strings.TrimSpace(parts[1]))
			if len(fingerprint) != 40 {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: invalid fingerprint length",
				)
			}
			for _, r := range fingerprint {
				if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'F') {
					return APTListDoctorRemoteProbe{}, fmt.Errorf(
						"APT list Doctor remote probe failed: invalid fingerprint value",
					)
				}
			}
			if seen["fpr:"+fingerprint] {
				return APTListDoctorRemoteProbe{}, fmt.Errorf(
					"APT list Doctor remote probe failed: duplicate fingerprint record",
				)
			}

			probe.KeyringFingerprints = append(
				probe.KeyringFingerprints,
				fingerprint,
			)
			seen["fpr:"+fingerprint] = true

		default:
			return APTListDoctorRemoteProbe{}, fmt.Errorf(
				"APT list Doctor remote probe failed: unknown probe record",
			)
		}
	}

	for _, required := range []string{
		"apt_get",
		"gpg",
		"file:source",
		"file:keyring",
	} {
		if !seen[required] {
			return APTListDoctorRemoteProbe{}, fmt.Errorf(
				"APT list Doctor remote probe failed: missing required probe record %q",
				required,
			)
		}
	}

	if !probe.GPGAvailable && len(probe.KeyringFingerprints) != 0 {
		return APTListDoctorRemoteProbe{}, fmt.Errorf(
			"APT list Doctor remote probe failed: fingerprints reported without gpg",
		)
	}

	return probe, nil
}

func parseAPTListDoctorRemoteFile(
	parts []string,
) (APTListDoctorRemoteFile, error) {
	if len(parts) != 3 {
		return APTListDoctorRemoteFile{}, fmt.Errorf(
			"APT list Doctor remote probe failed: invalid file fields",
		)
	}

	state := APTListDoctorFileState(strings.TrimSpace(parts[0]))
	switch state {
	case APTListDoctorFileStatePresent,
		APTListDoctorFileStateMissing,
		APTListDoctorFileStateSymlink,
		APTListDoctorFileStateNotRegular,
		APTListDoctorFileStateUnsafeOwner,
		APTListDoctorFileStateUnsafeMode,
		APTListDoctorFileStateUnreadable,
		APTListDoctorFileStateInvalid:
	default:
		return APTListDoctorRemoteFile{}, fmt.Errorf(
			"APT list Doctor remote probe failed: invalid file state",
		)
	}

	mode := strings.TrimSpace(parts[1])
	sizeText := strings.TrimSpace(parts[2])

	requiresMetadata := state == APTListDoctorFileStatePresent ||
		state == APTListDoctorFileStateUnsafeOwner ||
		state == APTListDoctorFileStateUnsafeMode ||
		state == APTListDoctorFileStateUnreadable

	if requiresMetadata && (mode == "" || sizeText == "") {
		return APTListDoctorRemoteFile{}, fmt.Errorf(
			"APT list Doctor remote probe failed: missing file metadata",
		)
	}
	if !requiresMetadata && (mode != "" || sizeText != "") {
		return APTListDoctorRemoteFile{}, fmt.Errorf(
			"APT list Doctor remote probe failed: unexpected file metadata",
		)
	}

	file := APTListDoctorRemoteFile{
		State: state,
		Mode:  mode,
	}

	if sizeText != "" {
		size, err := strconv.ParseInt(sizeText, 10, 64)
		if err != nil || size < 0 {
			return APTListDoctorRemoteFile{}, fmt.Errorf(
				"APT list Doctor remote probe failed: invalid file size",
			)
		}
		file.Size = size
	}

	return file, nil
}
