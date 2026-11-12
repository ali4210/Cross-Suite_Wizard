package repohealer

import (
	"fmt"
	"strings"
	"time"
)

// HashiCorpAPTListRepairApplyResult mirrors Deb822RepairApplyResult: the legacy APT-list case
// only ever needs to replace the pinned keyring file (the .list line's signed-by binding to
// that keyring path was already verified by ParseAPTListSourceReference/the APT-list Doctor
// before this action became reachable), so SourceFile is snapshotted defensively but is never
// rewritten.
type HashiCorpAPTListRepairApplyResult struct {
	Attempted       bool
	Applied         bool
	RolledBack      bool
	Snapshot        Snapshot
	ActionID        string
	ProfileID       string
	SourceFile      string
	KeyringPath     string
	Output          string
	VerificationOut string
	Error           error
}

// ApplyHashiCorpAPTListRepair downloads the HashiCorp signing key only from the pinned official
// URL (never a keyserver), verifies the full pinned fingerprint before installing anything,
// snapshots the source file and keyring first, installs the verified keyring atomically as
// root-owned mode 0644, verifies with apt-get update, and rolls back automatically on any
// failure.
func ApplyHashiCorpAPTListRepair(
	exec Executor,
	preflight HashiCorpAPTListRepairPreflight,
) HashiCorpAPTListRepairApplyResult {
	request := preflight.Request
	result := HashiCorpAPTListRepairApplyResult{
		Attempted:   true,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		SourceFile:  request.SourceFile,
		KeyringPath: request.KeyringPath,
	}

	if !preflight.Ready {
		result.Error = fmt.Errorf(
			"HashiCorp APT-list repair blocked: preflight is not ready: %s",
			strings.TrimSpace(preflight.Reason),
		)
		return result
	}

	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		result.Error = err
		return result
	}

	profile, ok := FindVendorProfileByID(ManagerAPT, request.ProfileID)
	if !ok || profile.ID != HashiCorpAPTListProfileID || profile.KeyURL != request.KeyURL ||
		profile.KeyringPath != request.KeyringPath {
		result.Error = fmt.Errorf(
			"HashiCorp APT-list repair blocked: verified profile binding changed before execution",
		)
		return result
	}

	if err := ensureAPTRepairUnlocked(exec); err != nil {
		result.Error = err
		return result
	}

	snapshotTargets := []string{request.SourceFile, request.KeyringPath}
	snapshot, err := CreateAPTFileSnapshot(exec, snapshotTargets)
	if err != nil {
		result.Error = fmt.Errorf(
			"HashiCorp APT-list repair blocked: could not create targeted APT snapshot: %w",
			err,
		)
		return result
	}
	result.Snapshot = snapshot

	tempDir := fmt.Sprintf(
		"/var/tmp/cross-suite-aptlist-repoheal-%s-%d",
		profile.ID,
		time.Now().UTC().UnixNano(),
	)

	script := fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
EXPECTED_FINGERPRINT=%q
TEMP_DIR=%q

KEYRING_DIR="$(dirname "$KEYRING_PATH")"
KEYRING_TMP=""

cleanup() {
	rm -rf "$TEMP_DIR"
	if [ -n "$KEYRING_TMP" ]; then
		rm -f "$KEYRING_TMP"
	fi
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR"
install -d -m 0755 "$KEYRING_DIR"

export GNUPGHOME="$TEMP_DIR/gnupg"
mkdir -p "$GNUPGHOME"
chmod 0700 "$GNUPGHOME"

curl -fsSL --proto '=https' --tlsv1.2 "$KEY_URL" \
	-o "$TEMP_DIR/vendor.asc"

test -s "$TEMP_DIR/vendor.asc"

MATCHED_FINGERPRINT=""
while IFS= read -r fingerprint; do
	[ -z "$fingerprint" ] && continue

	if [ "$fingerprint" = "$EXPECTED_FINGERPRINT" ]; then
		MATCHED_FINGERPRINT="$fingerprint"
		break
	fi
done < <(
	gpg --show-keys --with-colons --fingerprint "$TEMP_DIR/vendor.asc" \
	| awk -F: '$1 == "fpr" {print toupper($10)}'
)

if [ -z "$MATCHED_FINGERPRINT" ]; then
	echo "APTLIST_REPAIR_ERROR|fingerprint_mismatch|profile=$PROFILE_ID"
	exit 22
fi

gpg --dearmor --yes \
	--output "$TEMP_DIR/vendor.gpg" \
	"$TEMP_DIR/vendor.asc"

test -s "$TEMP_DIR/vendor.gpg"

KEYRING_TMP="$(mktemp "$KEYRING_DIR/.cross-suite-${PROFILE_ID}.keyring.XXXXXX")"
install -o root -g root -m 0644 \
	"$TEMP_DIR/vendor.gpg" \
	"$KEYRING_TMP"
test -s "$KEYRING_TMP"

mv -f "$KEYRING_TMP" "$KEYRING_PATH"
KEYRING_TMP=""

echo "APTLIST_REPAIR_APPLIED|$PROFILE_ID|fingerprint=$MATCHED_FINGERPRINT"
`,
		profile.ID,
		profile.KeyURL,
		request.KeyringPath,
		request.ExpectedFingerprint,
		tempDir,
	)

	output, err := exec.RunSudoWithLabel(
		script,
		"Restoring "+profile.DisplayName+" APT-list Signing Key",
	)
	result.Output = strings.TrimSpace(output)

	if err != nil || !hasHashiCorpAPTListRepairAppliedMarker(output, profile) {
		if err != nil {
			if strings.TrimSpace(output) != "" {
				result.Error = fmt.Errorf(
					"HashiCorp APT-list keyring repair failed: %w: %s",
					err,
					strings.TrimSpace(output),
				)
			} else {
				result.Error = fmt.Errorf(
					"HashiCorp APT-list keyring repair failed: %w",
					err,
				)
			}
		} else {
			result.Error = fmt.Errorf(
				"HashiCorp APT-list keyring repair failed: repair command did not report a valid APTLIST_REPAIR_APPLIED marker",
			)
		}
		rollbackHashiCorpAPTListRepair(exec, &result, snapshotTargets)
		return result
	}

	verificationOut, verifyErr := exec.RunSudoWithLabel(
		defaultAPTVerificationScript,
		"Verifying HashiCorp APT-list Repository Health",
	)
	result.VerificationOut = strings.TrimSpace(verificationOut)

	if verifyErr != nil ||
		strings.Contains(verificationOut, "NO_PUBKEY") ||
		strings.Contains(verificationOut, "BADSIG") ||
		strings.Contains(verificationOut, "EXPKEYSIG") ||
		strings.Contains(verificationOut, "Failed to fetch") {
		if verifyErr != nil {
			result.Error = fmt.Errorf(
				"post-repair HashiCorp APT-list verification failed: %w",
				verifyErr,
			)
		} else {
			result.Error = fmt.Errorf(
				"post-repair HashiCorp APT-list verification failed: repository trust or fetch errors were reported",
			)
		}
		rollbackHashiCorpAPTListRepair(exec, &result, snapshotTargets)
		return result
	}

	result.Applied = true
	return result
}

func rollbackHashiCorpAPTListRepair(
	exec Executor,
	result *HashiCorpAPTListRepairApplyResult,
	snapshotTargets []string,
) {
	rollbackErr := RestoreAPTFileSnapshot(exec, result.Snapshot, snapshotTargets)
	result.RolledBack = rollbackErr == nil

	if rollbackErr != nil {
		result.Error = fmt.Errorf(
			"%w; targeted HashiCorp APT-list rollback also failed: %v",
			result.Error,
			rollbackErr,
		)
	}
}

func hasHashiCorpAPTListRepairAppliedMarker(
	output string,
	profile VendorProfile,
) bool {
	prefix := "APTLIST_REPAIR_APPLIED|" + profile.ID + "|fingerprint="

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		fingerprint := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if fingerprint == "" {
			continue
		}

		if IsPinnedFingerprint(profile, fingerprint) {
			return true
		}
	}

	return false
}
